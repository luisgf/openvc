"""
tests/test_ebsi_live.py — the two live EBSI lanes of .github/workflows/live-ebsi.yml, and the
offline tests of everything they decide with (#326, ADR-0009 "What to watch").

Three lanes, one workflow, never on a pull request:

  * ``live``    — the legacy v5 smoke, ``test_live_resolve`` in test_ebsi_verifier.py. Untouched.
  * ``core-v1`` — ``test_live_core_v1_preprod``: from the VERIFIED Trusted Nodes List take two
    preprod nodes (different operators, ``/v1/alive`` healthy), read a DID document and a
    Trusted Issuers Registry record from each through ``DidRegistryCoreV1`` / ``TirCoreV1``,
    and require the two parsed results to agree. The alarm for the Core v1 shapes, the Problem
    Details ``type`` and the per-node hosts that the golden fixtures pin offline.
  * ``tnl-watch`` — ``test_live_tnl_watch``: verify the live list chain with the SHIPPED anchor
    and floors, a real clock and no stored state (the stateless caller of ADR-0009 D2), then
    turn red for each of: the list is within ``OPENVC_TNL_WARN_DAYS`` (default 14) of its
    ``expires``; ``tnl.json``'s ``version`` is not ``LAST_SEEN_TNL_VERSION``;
    ``trusted-keys.json``'s ``version`` is not ``LAST_SEEN_KEYS_VERSION``; the served
    ``keylist-key.asc`` is not the recorded file.

The job names say the cause. The verifier's own errors are never caught here: a signature
error with the shipped anchor is anchor drift, ``NodeListRollback`` is a shipped floor above
the live version (an outage by ADR-0009 D3), ``NodeListExpired`` is an expired list.

OFFLINE (always run, no socket: an autouse fixture refuses one): the pure functions
(``tnl_watch_findings``, ``parse_warn_days``, ``select_nodes``, ``diff_observations``, the
summary renderers), the real chain fixture of #319 through the real verifier with the clock
fixed inside its window, and the whole core-v1 flow against the RECORDED preprod bodies of
two nodes (``tests/fixtures/ebsi/core-v1/``) through real clients with an injected transport.
LIVE (opt-in): ``OPENVC_EBSI_LIVE=1``, exactly the pattern of ``test_live_resolve``. The
workflow selects a live test with ``-k live_core_v1`` or ``-k live_tnl_watch``, so no offline
test name below contains either string (a test pins that).

Bumping ``LAST_SEEN_*``: they are what the live lists were when this file was last touched
(measured 2026-10-19). A red ``LIST_VERSION`` or ``KEYS_VERSION`` means EBSI published a new
list: bump the constant in a test-only PR, re-record ``tests/fixtures/ebsi/tnl/`` by hand, and
raise ``LIST_VERSION_FLOOR`` / ``KEYS_VERSION_FLOOR`` at the next release only if the shipped
code should enforce the new minimum, and never above a version EBSI has published.

``tests/`` is not a package: nothing is imported from another test module.
"""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import hashlib
import inspect
import json
import logging
import os
import re
import socket
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence
from urllib.parse import urlsplit

import pytest

httpx = pytest.importorskip("httpx")

from openvc import _json  # noqa: E402
from openvc.did.base import DidResolutionError  # noqa: E402
from openvc.proof.vc_jwt import VcJwtProofSuite  # noqa: E402
from openvc_ebsi.errors import EbsiError, NodeListExpired  # noqa: E402
from openvc_ebsi.http import (  # noqa: E402
    TNL_HOST,
    EbsiHttpClient,
    HttpError,
    HttpForbiddenHost,
    HttpNotFound,
    HttpTransientExhausted,
    RetryPolicy,
    for_tnl,
    get_tnl_files,
)
from openvc_ebsi.models import IssuerRecord  # noqa: E402
from openvc_ebsi.nodes import (  # noqa: E402
    EUROPEUM_KEY_LIST_ANCHOR,
    KEYS_VERSION_FLOOR,
    LIST_VERSION_FLOOR,
    Accepted,
    Anchor,
    Node,
    VerifiedNodeList,
    verify_node_list,
)
from openvc_ebsi.versioning import (  # noqa: E402
    DidEbsiResolver,
    did_registry_adapter,
    tir_adapter,
)

HERE = Path(__file__).parent
TNL_FIXTURES = HERE / "fixtures" / "ebsi" / "tnl"
CORE_FIXTURES = HERE / "fixtures" / "ebsi" / "core-v1"

# --------------------------------------------------------------------------- #
# What the live lists were when this file was last touched (decision 2 of #326)
# --------------------------------------------------------------------------- #

#: ``tnl.json`` ``version``, measured 2026-10-19 (the recorded fixture is version 4).
LAST_SEEN_TNL_VERSION = 4
#: ``trusted-keys.json`` ``version`` (not ``tnl.json``'s ``keysVersion``), measured 2026-10-19.
LAST_SEEN_KEYS_VERSION = 1

DEFAULT_WARN_DAYS = 14
MAX_WARN_DAYS = 400
#: ADR "Fixtures plan": the preprod RootTAO, a DID document with a secp256k1 and a P-256 key.
DEFAULT_CORE_DID = "did:ebsi:zmaEptEHQRAmkJnFV6ki3io"
KEYLIST_KEY_URL = f"https://{TNL_HOST}/keylist-key.asc"
KEYLIST_KEY_MAX_BYTES = 8 * 1024        # the file is 1152 bytes; a test-side bound
WANT_NODES = 2

needs_live = pytest.mark.skipif(
    os.getenv("OPENVC_EBSI_LIVE") != "1", reason="live EBSI test is opt-in")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: The recorded ``keylist-key.asc`` of #319 (its digest is pinned in test_ebsi_tnl_golden.py).
RECORDED_KEYLIST_KEY_SHA256 = _sha256((TNL_FIXTURES / "keylist-key.asc").read_bytes())


# --------------------------------------------------------------------------- #
# The watch: a pure function (no library API)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Finding:
    """One reason to turn the watch red: a code and a one-line action."""
    code: str
    action: str

    def __str__(self) -> str:
        return f"{self.code}: {self.action}"


def _check_warn_days(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_WARN_DAYS:
        raise ValueError(
            f"warn_days must be an int from 1 to {MAX_WARN_DAYS}, not {value!r:.40}")
    return value


def parse_warn_days(text: str | None) -> int:
    """``OPENVC_TNL_WARN_DAYS``: unset or empty is the default (a ``schedule`` run has no
    dispatch input, and the runner then hands the job an empty string); anything else must
    be 1 to 4 ASCII digits in range, else ``ValueError``."""
    if text is None or text == "":
        return DEFAULT_WARN_DAYS
    if not isinstance(text, str) or re.fullmatch(r"[0-9]{1,4}", text) is None:
        raise ValueError(f"OPENVC_TNL_WARN_DAYS is not a whole number of days: {text!r:.40}")
    return _check_warn_days(int(text))


def _check_version(value: object, what: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{what} must be an int of at least 1, not {value!r:.40}")
    return value


def _check_digest(value: object, what: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{what} must be 64 lower-case hex characters, not {value!r:.80}")
    return value


def _check_instant(value: object, what: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{what} must be an aware datetime, not {value!r:.40}")
    return value


def tnl_watch_findings(
    *,
    now: datetime,
    expires: datetime,
    list_version: int,
    keys_version: int,
    keylist_key_sha256: str,
    warn_days: int,
    last_seen_list: int,
    last_seen_keys: int,
    recorded_keylist_key_sha256: str,
) -> list[Finding]:
    """Every reason to be red, in a fixed order: ``EXPIRING``, ``LIST_VERSION``,
    ``KEYS_VERSION``, ``ANCHOR_FILE``. Empty when the watch is green.

    ``expires - now <= warn_days`` days is ``EXPIRING``, an expired list included.
    ``list_version`` is ``tnl.json``'s ``version``; ``keys_version`` is
    ``trusted-keys.json``'s OWN ``version`` (the rotation signal the key-list key signs), never
    ``tnl.json``'s ``keysVersion``. A version that differs in either direction is a finding:
    higher means EBSI reissued, lower means a rollback or a stale mirror. Bad arguments
    (a ``bool`` or ``str`` ``warn_days``, an out-of-range one, a naive datetime, ...) raise
    ``ValueError`` rather than compare wrongly: a watch that cannot be trusted is worse than
    none."""
    days = _check_warn_days(warn_days)
    now = _check_instant(now, "now")
    expires = _check_instant(expires, "expires")
    live_list = _check_version(list_version, "list_version")
    live_keys = _check_version(keys_version, "keys_version")
    seen_list = _check_version(last_seen_list, "last_seen_list")
    seen_keys = _check_version(last_seen_keys, "last_seen_keys")
    served = _check_digest(keylist_key_sha256, "keylist_key_sha256")
    recorded = _check_digest(recorded_keylist_key_sha256, "recorded_keylist_key_sha256")

    findings: list[Finding] = []
    remaining = expires - now
    if remaining <= timedelta(days=days):
        left = ("already expired" if remaining <= timedelta(0)
                else f"{remaining.days} d {remaining.seconds // 3600} h away")
        findings.append(Finding("EXPIRING", (
            f"the node list expires {_instant_text(expires)} ({left}; warning at {days} d): "
            "look for a reissue on https://tnl.ebsi.eu; if none appears every strict client "
            "fails closed at that instant (ADR-0009 D5)")))
    if live_list != seen_list:
        findings.append(Finding("LIST_VERSION", (
            f"tnl.json is version {live_list}, last seen {seen_list}: bump "
            "LAST_SEEN_TNL_VERSION in tests/test_ebsi_live.py (test-only PR), re-record "
            "tests/fixtures/ebsi/tnl/, and raise LIST_VERSION_FLOOR at the next release only "
            "if it should enforce the new minimum (never above a published version)")))
    if live_keys != seen_keys:
        findings.append(Finding("KEYS_VERSION", (
            f"trusted-keys.json is version {live_keys}, last seen {seen_keys}: the custodians "
            "or the threshold may have changed; bump LAST_SEEN_KEYS_VERSION in "
            "tests/test_ebsi_live.py, re-record the fixtures, and raise KEYS_VERSION_FLOOR at "
            "the next release only if it should enforce the new minimum")))
    if served != recorded:
        findings.append(Finding("ANCHOR_FILE", (
            f"the served keylist-key.asc is sha256 {served}, the recorded one is {recorded}: "
            "the anchor is never refreshed from the network, and a change may be the switch to "
            "a qualified seal (ADR-0009 open question 7); compare the fingerprint with "
            "Europeum's published one, the maintainer decides")))
    return findings


def _instant_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


# --------------------------------------------------------------------------- #
# Node selection (an injected get_json, so the failure cases are offline)
# --------------------------------------------------------------------------- #

#: What a node can do wrong that is the NODE's failure: any typed error of the client (a 403,
#: a 5xx once the retries are spent, a 3xx, a non-JSON 200), a bare transport error.
NODE_ERRORS = (EbsiError, httpx.HTTPError, OSError)


@dataclass(frozen=True)
class NodeFailure:
    """Why a node was not used. ``kind`` is an exception class name or ``not-healthy``, and
    ``status`` the HTTP status when the exception carried one. Never a message and never a
    body: a node's firewall page (a measured 35 KB of HTML) is not parsed or reported."""
    host: str
    kind: str
    status: int | None

    def __str__(self) -> str:
        return f"{self.host}: {self.kind}" + ("" if self.status is None else f" {self.status}")


@dataclass(frozen=True)
class Selection:
    chosen: tuple[Node, ...]
    failures: tuple[NodeFailure, ...]
    skipped: tuple[str, ...]            # hosts passed over: an operator already chosen


def _status_of(exc: BaseException) -> int | None:
    status = getattr(exc, "status", None)
    return status if type(status) is int else None


def select_nodes(nodes: Sequence[Node], get_json: Callable[[str], Any],
                 *, want: int = WANT_NODES) -> Selection:
    """The first *want* nodes, in list order, with different ``organisation`` whose
    ``GET /v1/alive`` answers ``health_global`` 1. Stops probing once it has them. A node
    that fails (any of :data:`NODE_ERRORS`, or a 200 that does not say healthy) is recorded and
    passed over; a node of an operator already chosen is skipped without a request, so an
    operator whose first node was down can still be represented by its second."""
    chosen: list[Node] = []
    failures: list[NodeFailure] = []
    skipped: list[str] = []
    organisations: set[str] = set()
    for node in nodes:
        if len(chosen) >= want:
            break
        if node.organisation in organisations:
            skipped.append(node.host)
            continue
        try:
            body = get_json(f"{node.origin}/v1/alive")
        except NODE_ERRORS as exc:
            failures.append(NodeFailure(node.host, type(exc).__name__, _status_of(exc)))
            continue
        health = body.get("health_global") if isinstance(body, dict) else None
        if type(health) is not int or health != 1:
            failures.append(NodeFailure(node.host, "not-healthy", 200))
            continue
        organisations.add(node.organisation)
        chosen.append(node)
    return Selection(tuple(chosen), tuple(failures), tuple(skipped))


class NodeClients:
    """One :class:`EbsiHttpClient` per node, each allow-listing that node's host alone
    (ADR-0009 D1), built on first use. ``get_json`` routes by the URL's host and refuses any
    host that is not a node of the verified list, so a hand-written URL cannot reach elsewhere
    through it. ``factory`` is the seam for tests."""

    def __init__(self, nodes: Sequence[Node],
                 factory: Callable[[str], EbsiHttpClient] | None = None) -> None:
        self._hosts = frozenset(node.host for node in nodes)
        self._factory = factory or (lambda host: EbsiHttpClient(allowed_hosts={host}))
        self._clients: dict[str, EbsiHttpClient] = {}

    def get_json(self, url: str) -> dict[str, Any]:
        host = (urlsplit(url).hostname or "").lower()
        if host not in self._hosts:
            raise AssertionError(f"not a node of the verified list: {host!r:.80}")
        client = self._clients.get(host)
        if client is None:
            client = self._clients[host] = self._factory(host)
        return client.get_json(url)

    def close(self) -> None:
        for client in self._clients.values():
            client.close()
        self._clients.clear()


# --------------------------------------------------------------------------- #
# Reading a DID document and an issuer record from a node, and comparing two nodes
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Observation:
    """What one node answered, reduced to what two honest nodes must agree on."""
    host: str
    did_id: str
    methods: tuple[tuple[str, str, str, str], ...]     # (id, type, controller, JWK), by id
    record_did: str
    has_attributes: bool
    accreditations: tuple[tuple[Any, ...], ...]        # one tuple per accreditation, sorted


def observe_node(node: Node, get_json: Callable[[str], Any], did: str) -> Observation:
    """Resolve *did* and read its issuer record from *node* on the Core v1 lane.

    Single-level trust only (``peek_claims``, no ``trust_anchors=``): recursive trust on a
    Core v1 root is a separate opt-in (#323)."""
    resolver = DidEbsiResolver(
        get_json, decode_jwt=VcJwtProofSuite().peek_claims, base=node.origin,
        didr=did_registry_adapter("core-v1"), tir=tir_adapter("core-v1"))
    doc = resolver.resolve(did)
    assert doc.id == did, f"{node.host}: the DID document names another DID"
    assert doc.verification_methods, f"{node.host}: the DID document has no verification method"
    record = resolver.issuer_record(did)
    assert record.did == did, f"{node.host}: the issuer record names another DID"
    if record.has_attributes:
        assert record.accreditations, f"{node.host}: hasAttributes, but the walk found none"
    return _observation(node.host, doc.id, doc.verification_methods, record)


def _observation(host: str, did_id: str, methods: Sequence[Any], record: IssuerRecord
                 ) -> Observation:
    return Observation(
        host=host,
        did_id=did_id,
        methods=tuple(sorted(
            (vm.id, vm.type, vm.controller,
             json.dumps(vm.public_key_jwk, sort_keys=True, separators=(",", ":")))
            for vm in methods)),
        record_did=record.did,
        has_attributes=record.has_attributes,
        accreditations=tuple(sorted(
            (a.attribute_id, a.issuer_type, a.tao, a.root_tao, a.credential_types,
             a.credential_jwt) for a in record.accreditations)),
    )


def diff_observations(first: Observation, second: Observation) -> list[str]:
    """The fields on which two nodes disagree, by NAME (never by value: the values are a
    node's own words). Empty when they agree. Ordering is not compared: a list a ledger
    returns in another order is not drift."""
    differences = []
    for label, left, right in (
        ("DID document id", first.did_id, second.did_id),
        ("verification methods (ids, types, controllers, keys)", first.methods, second.methods),
        ("issuer record DID", first.record_did, second.record_did),
        ("issuer record hasAttributes", first.has_attributes, second.has_attributes),
        ("issuer record accreditations", first.accreditations, second.accreditations),
    ):
        if left != right:
            differences.append(f"{label}: {first.host} and {second.host} differ")
    return differences


@dataclass
class CoreRun:
    """What one pass of the core-v1 smoke saw, filled in as it goes, so the step summary can
    be written even when a read raises."""
    selection: Selection | None = None
    reads: list[tuple[str, str]] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    differences: list[str] = field(default_factory=list)
    counts: Counter[str] = field(default_factory=Counter)


def probe_client(host: str) -> EbsiHttpClient:
    """The ``/v1/alive`` probe's client: one attempt, so a node that does not answer costs
    one timeout and not three (the reads keep the shipped retry policy)."""
    return EbsiHttpClient(allowed_hosts={host}, retry=RetryPolicy(attempts=1))


def run_core_v1(run: CoreRun, nodes: Sequence[Node], did: str) -> None:
    """Select two healthy nodes of different operators, read *did* from each, compare. GET
    only, sequential, a client per node and per purpose. A read that fails after its node
    answered ``/v1/alive`` is not failed over: it is the drift this lane exists to see."""
    probes = NodeClients(nodes, probe_client)
    readers = NodeClients(nodes)
    try:
        with count_requests([node.host for node in nodes]) as counted:
            run.counts = counted
            run.selection = select_nodes(nodes, probes.get_json)
            if len(run.selection.chosen) < WANT_NODES:
                run.reads = [(node.host, "alive, not read") for node in run.selection.chosen]
                return
            for node in run.selection.chosen:
                try:
                    run.observations.append(observe_node(node, readers.get_json, did))
                except Exception as exc:       # the summary names the node, then this re-raises
                    run.reads.append((node.host, f"read failed: {type(exc).__name__}"))
                    raise
                run.reads.append((node.host, "read ok"))
        run.differences = diff_observations(*run.observations)
    finally:
        probes.close()
        readers.close()


def too_few_nodes_message(selection: Selection) -> str:
    return (f"fewer than {WANT_NODES} usable preprod nodes (different operators, /v1/alive "
            f"healthy): {len(selection.chosen)} found; failures: "
            + ("; ".join(str(failure) for failure in selection.failures) or "none"))


# --------------------------------------------------------------------------- #
# Counting the requests a run makes (httpx logs one INFO line per response)
# --------------------------------------------------------------------------- #

_REQUEST_LINE = re.compile(r"HTTP Request: [A-Z]+ https://([A-Za-z0-9.-]+)(?::443)?[/?#\s]")


class RequestCounter(logging.Handler):
    """Counts the ``HTTP Request:`` lines httpx logs, per host, for the given hosts only: the
    real number of responses received, retries included (a call counter would miss them)."""

    def __init__(self, hosts: Sequence[str]) -> None:
        super().__init__(level=logging.INFO)
        self._hosts = frozenset(host.lower() for host in hosts)
        self.counts: Counter[str] = Counter()

    def emit(self, record: logging.LogRecord) -> None:
        match = _REQUEST_LINE.match(record.getMessage())
        if match is not None and match.group(1).lower() in self._hosts:
            self.counts[match.group(1).lower()] += 1


@contextlib.contextmanager
def count_requests(hosts: Sequence[str]) -> Iterator[Counter[str]]:
    handler = RequestCounter(hosts)
    logger = logging.getLogger("httpx")
    level = logger.level
    logger.addHandler(handler)
    if not logger.isEnabledFor(logging.INFO):
        logger.setLevel(logging.INFO)
    try:
        yield handler.counts
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


# --------------------------------------------------------------------------- #
# The step summary: validated values only
# --------------------------------------------------------------------------- #

_CELL = re.compile(r"[A-Za-z0-9 ._:/+()=,-]{0,200}")


def _cell(value: object) -> str:
    """A value that is safe in a Markdown table cell: an int, an aware datetime from the
    verifier, or a short plain-ASCII string (a host the verifier accepted, an exception class
    name, a DID). Anything else is not shown, so a hostile response body, which never reaches
    this function, could not reach the page either."""
    if type(value) is int:
        return str(value)
    if isinstance(value, datetime) and value.tzinfo is not None:
        return _instant_text(value)
    if type(value) is str and _CELL.fullmatch(value) is not None:
        return value
    return "(not shown)"


def render_tnl_summary(
    *, result: VerifiedNodeList, now: datetime, threshold: int, warn_days: int,
    keylist_key_sha256: str, requests: Counter[str], findings: Sequence[Finding],
) -> str:
    left = result.expires - now
    days_left = left.days if left >= timedelta(0) else "expired"
    served = "the recorded file" if keylist_key_sha256 == RECORDED_KEYLIST_KEY_SHA256 \
        else "NOT the recorded file"
    rows = [
        ("tnl.json version", f"{_cell(result.version)} (last seen {_cell(LAST_SEEN_TNL_VERSION)};"
                             f" shipped floor {_cell(LIST_VERSION_FLOOR)}, lag"
                             f" {_cell(LAST_SEEN_TNL_VERSION - LIST_VERSION_FLOOR)})"),
        ("issued", _cell(result.issued)),
        ("expires", _cell(result.expires)),
        ("days left", f"{_cell(days_left)} (warning at {_cell(warn_days)})"),
        ("trusted-keys.json version",
         f"{_cell(result.accepted_keys.version)} (last seen {_cell(LAST_SEEN_KEYS_VERSION)};"
         f" shipped floor {_cell(KEYS_VERSION_FLOOR)}, lag"
         f" {_cell(LAST_SEEN_KEYS_VERSION - KEYS_VERSION_FLOOR)})"),
        ("custodian threshold", _cell(threshold)),
        ("keylist-key.asc", served),
        ("requests", _requests_text(requests)),
    ]
    lines = ["### TNL watch", "", "| | |", "|---|---|"]
    lines += [f"| {label} | {value} |" for label, value in rows]
    lines += ["", "**Findings:** none" if not findings else "**Findings:**", ""]
    lines += [f"- `{_cell(finding.code)}`" for finding in findings]
    return "\n".join(lines) + "\n"


def render_core_summary(
    *, did: str, selection: Selection | None, reads: Sequence[tuple[str, str]],
    requests: Counter[str], differences: Sequence[str],
) -> str:
    """*reads* is ``(host, outcome)`` for each chosen node, the outcome a short fixed phrase
    or an exception class name."""
    lines = ["### Core v1 preprod smoke", "", f"DID: `{_cell(did)}`", "",
             "| node | outcome | requests |", "|---|---|---|"]
    for host, outcome in reads:
        lines.append(f"| {_cell(host)} | {_cell(outcome)} | {_cell(requests.get(host, 0))} |")
    if selection is not None:
        for failure in selection.failures:
            lines.append(f"| {_cell(failure.host)} | not used: {_cell(failure.kind)}"
                         f"{'' if failure.status is None else ' ' + _cell(failure.status)}"
                         f" | {_cell(requests.get(failure.host, 0))} |")
        if selection.skipped:
            lines += ["", f"Passed over without a request (same operator as a chosen node): "
                          f"{_cell(len(selection.skipped))}"]
    lines += ["", "**Differences between the two nodes:** none" if not differences
              else "**Differences between the two nodes:**"]
    lines += [f"- {_cell(item)}" for item in differences]
    return "\n".join(lines) + "\n"


def _requests_text(requests: Counter[str]) -> str:
    if not requests:
        return "0"
    return ", ".join(f"{_cell(host)}: {_cell(count)}" for host, count in sorted(requests.items()))


def write_step_summary(markdown: str) -> None:
    """Append to ``$GITHUB_STEP_SUMMARY`` when the runner sets it (and nowhere else). Only the
    two live tests call this: ``ci.yml`` runs the offline suite on a runner that sets the
    variable too, and must not write a page."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(markdown + "\n")


# --------------------------------------------------------------------------- #
# The list chain: fetched as served, verified as the stateless caller
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Chain:
    """The five files of ``https://tnl.ebsi.eu/``, exactly as served. UNTRUSTED until
    :func:`verify_chain` accepts them. ``keylist_key`` is never given to the verifier (the
    anchor is the shipped one); it is only hashed, against the recorded file."""
    tnl: bytes
    tnl_sig: bytes
    keys: bytes
    keys_sig: bytes
    keylist_key: bytes


def verify_chain(chain: Chain, *, now: datetime, environment: str = "preprod") -> VerifiedNodeList:
    """The stateless caller of ADR-0009 D2: the shipped anchor and floors, the real *now*,
    no ``last_accepted_*`` and no ``max_age``. Its errors are never caught by the tests."""
    return verify_node_list(
        tnl=chain.tnl, tnl_sig=chain.tnl_sig, keys=chain.keys, keys_sig=chain.keys_sig,
        environment=environment, now=now, last_accepted_list=None, last_accepted_keys=None)


def fixture_chain() -> Chain:
    def read(name: str) -> bytes:
        return (TNL_FIXTURES / name).read_bytes()
    return Chain(read("tnl.json"), read("tnl.json.sig"), read("trusted-keys.json"),
                 read("trusted-keys.json.sig"), read("keylist-key.asc"))


def fetch_chain() -> tuple[Chain, Counter[str]]:
    """Five GETs to ``tnl.ebsi.eu`` and nowhere else (never the node set, ADR-0009 D4),
    through the shipped client: redirects off, a 200 or an error, the default User-Agent, the
    per-file caps. Returns the bytes with the number of responses counted."""
    with count_requests([TNL_HOST]) as counts, for_tnl() as client:
        files = get_tnl_files(client)
        key = client.get_bytes(KEYLIST_KEY_URL, max_bytes=KEYLIST_KEY_MAX_BYTES).body
    bodies = {name: response.body for name, response in files.items()}
    assert key is not None and all(body is not None for body in bodies.values())
    return Chain(bodies["tnl.json"], bodies["tnl.json.sig"],  # type: ignore[arg-type]
                 bodies["trusted-keys.json"], bodies["trusted-keys.json.sig"], key), counts


def key_list_threshold(chain: Chain) -> int:
    """``threshold`` of an ACCEPTED ``trusted-keys.json`` (read after the verifier accepted
    it, through the bounded loader), for the summary only."""
    threshold = _json.loads(chain.keys, reject_ambiguous=True)["threshold"]
    assert type(threshold) is int
    return threshold


def watch(result: VerifiedNodeList, chain: Chain, *, now: datetime, warn_days: int,
          last_seen_list: int = LAST_SEEN_TNL_VERSION,
          last_seen_keys: int = LAST_SEEN_KEYS_VERSION) -> list[Finding]:
    """The live watch's decision: the verified result and the served key file against the
    constants of this file. ``result.accepted_keys.version`` is the key list's own version;
    ``result.keys_version`` is the ``keysVersion`` that ``tnl.json`` names, which is not the
    rotation signal."""
    return tnl_watch_findings(
        now=now, expires=result.expires, list_version=result.version,
        keys_version=result.accepted_keys.version,
        keylist_key_sha256=_sha256(chain.keylist_key), warn_days=warn_days,
        last_seen_list=last_seen_list, last_seen_keys=last_seen_keys,
        recorded_keylist_key_sha256=RECORDED_KEYLIST_KEY_SHA256)


# =========================================================================== #
# LIVE (opt-in): OPENVC_EBSI_LIVE=1. Each reaches public, read-only, unauthenticated hosts.
# =========================================================================== #

@pytest.fixture(scope="module")
def live_chain() -> tuple[Chain, Counter[str]]:
    """The five files, fetched once per pytest process (the two workflow jobs are two
    processes, each fetching its own). Requested only by the live tests, which the skipif
    mark skips before any fixture runs."""
    return fetch_chain()


@needs_live
def test_live_core_v1_preprod(live_chain: tuple[Chain, Counter[str]]) -> None:
    chain, _ = live_chain
    result = verify_chain(chain, now=datetime.now(timezone.utc))
    did = os.getenv("OPENVC_EBSI_CORE_DID", DEFAULT_CORE_DID)
    run = CoreRun()
    try:
        run_core_v1(run, result.nodes, did)
    finally:
        write_step_summary(render_core_summary(
            did=did, selection=run.selection, reads=run.reads, requests=run.counts,
            differences=run.differences))
    assert run.selection is not None
    if len(run.selection.chosen) < WANT_NODES:
        pytest.fail(too_few_nodes_message(run.selection), pytrace=False)
    assert not run.differences, "; ".join(run.differences)


@needs_live
def test_live_tnl_watch(live_chain: tuple[Chain, Counter[str]]) -> None:
    chain, requests = live_chain
    now = datetime.now(timezone.utc)
    warn_days = parse_warn_days(os.getenv("OPENVC_TNL_WARN_DAYS"))
    result = verify_chain(chain, now=now)              # never caught: see the module docstring
    findings = watch(result, chain, now=now, warn_days=warn_days)
    write_step_summary(render_tnl_summary(
        result=result, now=now, threshold=key_list_threshold(chain), warn_days=warn_days,
        keylist_key_sha256=_sha256(chain.keylist_key), requests=requests, findings=findings))
    if findings:
        pytest.fail("\n".join(str(finding) for finding in findings), pytrace=False)


# =========================================================================== #
# OFFLINE
# =========================================================================== #

@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """The default suite makes no request: a socket connect or a name lookup fails the test."""
    if request.node.name in LIVE_TESTS:
        return                      # skipped unless OPENVC_EBSI_LIVE=1, and then meant to connect

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the offline suite opened a socket or resolved a name")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
EXPIRES = datetime(2027, 1, 4, 13, 33, 18, tzinfo=timezone.utc)      # the recorded list's
FIXTURE_LIST_VERSION = 4
FIXTURE_KEYS_VERSION = 1
SECOND = timedelta(seconds=1)
H1 = "a" * 64
H2 = "b" * 64


def _findings(**over: Any) -> list[Finding]:
    args: dict[str, Any] = dict(
        now=NOW, expires=EXPIRES, list_version=4, keys_version=1, keylist_key_sha256=H1,
        warn_days=14, last_seen_list=4, last_seen_keys=1, recorded_keylist_key_sha256=H1)
    args.update(over)
    return tnl_watch_findings(**args)


def _codes(findings: list[Finding]) -> list[str]:
    return [finding.code for finding in findings]


# ---- warn_days and OPENVC_TNL_WARN_DAYS: bad values are ValueError, exactly --------------

BAD_WARN_DAYS = [True, False, "14", 14.0, 0, -1, 401, 10**9, None, b"14", [14]]


@pytest.mark.parametrize("value", BAD_WARN_DAYS, ids=repr)
def test_warn_days_of_the_wrong_type_or_range_is_a_value_error(value: object) -> None:
    with pytest.raises(ValueError) as caught:
        _findings(warn_days=value)
    assert type(caught.value) is ValueError


@pytest.mark.parametrize("text", [
    "abc", "1.5", " 14", "14 ", "+14", "-1", "0", "401", "00401", "٣", "1_0", "0x10", "1e1",
    "14\n", "99999", "fourteen"])
def test_an_unparseable_warn_days_environment_value_is_a_value_error(text: str) -> None:
    with pytest.raises(ValueError) as caught:
        parse_warn_days(text)
    assert type(caught.value) is ValueError


def test_warn_days_environment_value_parses_and_defaults() -> None:
    assert parse_warn_days(None) == 14
    assert parse_warn_days("") == 14            # a schedule run: the dispatch input is empty
    assert [parse_warn_days(t) for t in ("14", "365", "400", "1", "0014")] == [
        14, 365, 400, 1, 14]


def test_the_edges_of_warn_days_are_accepted() -> None:
    assert _codes(_findings(warn_days=1, expires=NOW + timedelta(days=1))) == ["EXPIRING"]
    assert _codes(_findings(warn_days=400, expires=NOW + timedelta(days=401))) == []


@pytest.mark.parametrize("name,value", [
    ("list_version", True), ("list_version", 0), ("list_version", "4"), ("list_version", 4.0),
    ("keys_version", True), ("keys_version", 0), ("keys_version", None),
    ("last_seen_list", True), ("last_seen_list", -1), ("last_seen_keys", "1"),
    ("keylist_key_sha256", "A" * 64), ("keylist_key_sha256", "a" * 63),
    ("keylist_key_sha256", b"a" * 64), ("recorded_keylist_key_sha256", None),
    ("recorded_keylist_key_sha256", ("a" * 64) + "\n"),
    ("now", datetime(2026, 10, 16, 12, 0, 0)), ("now", "2026-10-16T12:00:00Z"),
    ("expires", datetime(2027, 1, 4, 13, 33, 18)), ("expires", None),
])
def test_a_malformed_argument_is_a_value_error_not_a_wrong_comparison(
        name: str, value: object) -> None:
    with pytest.raises(ValueError) as caught:
        _findings(**{name: value})
    assert type(caught.value) is ValueError


# ---- EXPIRING: exactly warn_days is red, one second more is not --------------------------

def test_exactly_warn_days_before_expiry_is_expiring() -> None:
    assert _codes(_findings(now=EXPIRES - timedelta(days=14))) == ["EXPIRING"]


def test_one_second_outside_warn_days_is_not_expiring() -> None:
    assert _findings(now=EXPIRES - timedelta(days=14) - SECOND) == []
    assert _codes(_findings(now=EXPIRES - timedelta(days=14) + SECOND)) == ["EXPIRING"]


@pytest.mark.parametrize("remaining", [timedelta(0), -SECOND, -timedelta(days=30)], ids=repr)
def test_an_expired_list_is_expiring(remaining: timedelta) -> None:
    findings = _findings(now=EXPIRES - remaining)
    assert _codes(findings) == ["EXPIRING"]
    assert "already expired" in findings[0].action


def test_expiring_names_the_days_left_and_the_instant() -> None:
    action = _findings(now=EXPIRES - timedelta(days=7, hours=7))[0].action
    assert "2027-01-04T13:33:18Z" in action and "7 d 7 h away" in action


# ---- the version and anchor-file findings -------------------------------------------------

@pytest.mark.parametrize("live", [3, 5])
def test_a_list_version_that_moved_either_way_is_a_finding(live: int) -> None:
    findings = _findings(list_version=live)
    assert _codes(findings) == ["LIST_VERSION"]
    assert f"version {live}, last seen 4" in findings[0].action


@pytest.mark.parametrize("live", [2, 3])
def test_a_key_list_version_that_moved_is_a_finding(live: int) -> None:
    assert _codes(_findings(keys_version=live)) == ["KEYS_VERSION"]


def test_the_key_list_version_is_compared_to_its_own_last_seen_value() -> None:
    # tnl.json's keysVersion is not an input at all; the two last-seen values are independent
    assert _codes(_findings(list_version=4, keys_version=1, last_seen_list=1,
                            last_seen_keys=4)) == ["LIST_VERSION", "KEYS_VERSION"]


def test_a_different_key_file_is_a_finding_and_names_both_digests() -> None:
    findings = _findings(keylist_key_sha256=H2)
    assert _codes(findings) == ["ANCHOR_FILE"]
    assert H1 in findings[0].action and H2 in findings[0].action


def test_all_four_findings_come_in_a_fixed_order() -> None:
    findings = _findings(now=EXPIRES, list_version=9, keys_version=9, keylist_key_sha256=H2)
    assert _codes(findings) == ["EXPIRING", "LIST_VERSION", "KEYS_VERSION", "ANCHOR_FILE"]
    assert all(finding.action and "\n" not in finding.action for finding in findings)


def test_a_quiet_watch_has_no_findings() -> None:
    assert _findings() == []


# ---- node selection ----------------------------------------------------------------------

def _node(i: int, org: str | None = None) -> Node:
    host = f"api-preprod.ebsi.node{i}.example"
    return Node(f"https://{host}", host, "PT", org if org is not None else f"Operator {i}")


ALIVE = {"health_global": 1}


class Probe:
    """A get_json stub: URL -> a body to return or an exception to raise; records the calls."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def __call__(self, url: str) -> Any:
        self.calls.append(url)
        answer = self.answers.get(url, HttpNotFound("no route", status=404, url=url))
        if isinstance(answer, BaseException):
            raise answer
        return answer


def _alive_url(node: Node) -> str:
    return f"{node.origin}/v1/alive"


@pytest.mark.parametrize("failure,kind,status", [
    (HttpError("unexpected status 403", status=403, url="x", problem_type="urn:evil"),
     "HttpError", 403),
    (HttpError("unexpected status 301", status=301, url="x"), "HttpError", 301),
    (HttpTransientExhausted("gave up after 3 attempts: transient", url="x"),
     "HttpTransientExhausted", None),
    (httpx.ConnectError("refused"), "ConnectError", None),
    (ConnectionResetError("reset"), "ConnectionResetError", None),
], ids=["403", "3xx", "5xx-exhausted", "transport", "reset"])
def test_a_failing_first_node_is_passed_over_and_the_next_two_are_used(
        failure: Exception, kind: str, status: int | None) -> None:
    nodes = [_node(1), _node(2), _node(3)]
    probe = Probe({_alive_url(nodes[0]): failure, _alive_url(nodes[1]): ALIVE,
                   _alive_url(nodes[2]): ALIVE})
    selection = select_nodes(nodes, probe)
    assert [n.host for n in selection.chosen] == [nodes[1].host, nodes[2].host]
    assert selection.failures == (NodeFailure(nodes[0].host, kind, status),)
    assert probe.calls == [_alive_url(n) for n in nodes]


def test_two_nodes_of_one_operator_count_once_and_the_second_is_not_probed() -> None:
    nodes = [_node(1, "Same"), _node(2, "Same"), _node(3, "Other")]
    probe = Probe({_alive_url(n): ALIVE for n in nodes})
    selection = select_nodes(nodes, probe)
    assert [n.host for n in selection.chosen] == [nodes[0].host, nodes[2].host]
    assert selection.skipped == (nodes[1].host,)
    assert probe.calls == [_alive_url(nodes[0]), _alive_url(nodes[2])]


def test_an_operator_whose_first_node_is_down_can_be_represented_by_its_second() -> None:
    nodes = [_node(1, "A"), _node(2, "A"), _node(3, "B")]
    probe = Probe({_alive_url(nodes[0]): HttpTransientExhausted("x", url="x"),
                   _alive_url(nodes[1]): ALIVE, _alive_url(nodes[2]): ALIVE})
    selection = select_nodes(nodes, probe)
    assert [n.host for n in selection.chosen] == [nodes[1].host, nodes[2].host]
    assert selection.skipped == ()


def test_fewer_than_two_usable_nodes_names_each_failure() -> None:
    nodes = [_node(1), _node(2), _node(3), _node(4)]
    probe = Probe({
        _alive_url(nodes[0]): HttpError("unexpected status 403", status=403, url="x"),
        _alive_url(nodes[1]): HttpTransientExhausted("x", url="x"),
        _alive_url(nodes[2]): {"health_global": 0},
        _alive_url(nodes[3]): ALIVE,
    })
    selection = select_nodes(nodes, probe)
    assert [n.host for n in selection.chosen] == [nodes[3].host]
    assert [str(f) for f in selection.failures] == [
        f"{nodes[0].host}: HttpError 403",
        f"{nodes[1].host}: HttpTransientExhausted",
        f"{nodes[2].host}: not-healthy 200",
    ]


@pytest.mark.parametrize("body", [
    {"health_global": 0}, {"health_global": True}, {"health_global": "1"},
    {"health_global": 1.0}, {"health_global": None}, {}, {"health": 1}, [1], "ok", None, 1,
], ids=repr)
def test_a_200_that_does_not_say_healthy_is_not_healthy(body: object) -> None:
    node = _node(1)
    selection = select_nodes([node], Probe({_alive_url(node): body}))
    assert selection.chosen == ()
    assert selection.failures == (NodeFailure(node.host, "not-healthy", 200),)


def test_a_healthy_body_may_carry_other_members() -> None:
    node = _node(1)
    body = {"health_global": 1, "version": "x"}
    assert select_nodes([node], Probe({_alive_url(node): body}), want=1).chosen == (node,)


def test_a_403_body_is_neither_parsed_nor_reported() -> None:
    node = _node(1)
    waf = "<html><title>Web Application Firewall</title></html>"
    failure = HttpError(waf, status=403, url=waf, problem_type="urn:ebsi:problems:" + waf)
    selection = select_nodes([node], Probe({_alive_url(node): failure}))
    rendered = repr(selection) + str(selection.failures[0])
    assert "Firewall" not in rendered and "urn:ebsi" not in rendered
    assert selection.failures == (NodeFailure(node.host, "HttpError", 403),)


def test_a_status_that_is_not_an_int_is_not_reported() -> None:
    node = _node(1)
    failure = HttpError("x", status=True)       # type: ignore[arg-type]
    assert select_nodes([node], Probe({_alive_url(node): failure})).failures[0].status is None


def test_selection_stops_probing_once_it_has_enough() -> None:
    nodes = [_node(i) for i in range(1, 6)]
    probe = Probe({_alive_url(n): ALIVE for n in nodes})
    assert len(select_nodes(nodes, probe).chosen) == 2
    assert probe.calls == [_alive_url(nodes[0]), _alive_url(nodes[1])]


def test_a_bug_in_the_fetch_is_not_swallowed_as_a_node_failure() -> None:
    node = _node(1)
    with pytest.raises(KeyError):
        select_nodes([node], Probe({_alive_url(node): KeyError("bug")}))


# ---- one client per node, routed by host -------------------------------------------------

class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host, self.urls, self.closed = host, [], False

    def get_json(self, url: str) -> dict[str, Any]:
        self.urls.append(url)
        return {"host": self.host}

    def close(self) -> None:
        self.closed = True


def test_node_clients_route_by_host_build_one_client_per_node_and_close_them() -> None:
    nodes = [_node(1), _node(2)]
    built: list[_FakeClient] = []

    def factory(host: str) -> _FakeClient:
        built.append(_FakeClient(host))
        return built[-1]

    clients = NodeClients(nodes, factory)          # type: ignore[arg-type]
    assert clients.get_json(f"{nodes[1].origin}/v1/alive") == {"host": nodes[1].host}
    clients.get_json(f"{nodes[1].origin}/v1/x")
    clients.get_json(f"{nodes[0].origin}/v1/alive")
    assert [c.host for c in built] == [nodes[1].host, nodes[0].host]
    assert built[0].urls == [f"{nodes[1].origin}/v1/alive", f"{nodes[1].origin}/v1/x"]
    clients.close()
    assert all(c.closed for c in built)


@pytest.mark.parametrize("url", [
    "https://tnl.ebsi.eu/tnl.json", "https://evil.example/v1/alive", "http://", "/v1/alive",
    "https://api-preprod.ebsi.node1.example.evil.example/v1/alive"])
def test_node_clients_refuse_a_host_that_is_not_a_verified_node(url: str) -> None:
    built: list[str] = []
    clients = NodeClients([_node(1)], lambda host: built.append(host))       # type: ignore
    with pytest.raises(AssertionError):
        clients.get_json(url)
    assert built == []


def test_the_default_node_client_allow_lists_that_node_alone(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _transport(monkeypatch)
    clients = NodeClients([NODE_GRNET, NODE_INCM])
    try:
        assert clients.get_json(f"{NODE_GRNET.origin}/v1/alive") == {"health_global": 1}
        built = clients._clients[NODE_GRNET.host]
        assert built.allowed_hosts == frozenset({NODE_GRNET.host})
        with pytest.raises(HttpForbiddenHost):          # the one-host list refuses its sibling
            built.get_json(f"{NODE_INCM.origin}/v1/alive")
    finally:
        clients.close()


# ---- comparing two nodes -----------------------------------------------------------------

def _obs(**over: Any) -> Observation:
    args: dict[str, Any] = dict(
        host="a.example", did_id="did:ebsi:zX", methods=(("id", "t", "c", "{}"),),
        record_did="did:ebsi:zX", has_attributes=True, accreditations=(("h", "RootTAO"),))
    args.update(over)
    return Observation(**args)


def test_two_equal_observations_have_no_differences() -> None:
    assert diff_observations(_obs(), _obs(host="b.example")) == []


@pytest.mark.parametrize("over,label", [
    ({"did_id": "did:ebsi:zY"}, "DID document id"),
    ({"methods": ()}, "verification methods"),
    ({"methods": (("id", "t", "c", '{"x":"2"}'),)}, "verification methods"),
    ({"record_did": "did:ebsi:zY"}, "issuer record DID"),
    ({"has_attributes": False}, "issuer record hasAttributes"),
    ({"accreditations": ()}, "issuer record accreditations"),
    ({"accreditations": (("h", "TAO"),)}, "issuer record accreditations"),
])
def test_a_field_that_differs_is_named_by_label_and_hosts_never_by_value(
        over: dict[str, Any], label: str) -> None:
    differences = diff_observations(_obs(), _obs(host="b.example", **over))
    assert len(differences) == 1 and differences[0].startswith(label)
    assert "a.example" in differences[0] and "b.example" in differences[0]
    for value in over.values():
        assert repr(value) not in differences[0]


def test_every_difference_is_reported_at_once() -> None:
    differences = diff_observations(
        _obs(), _obs(host="b.example", did_id="did:ebsi:zY", has_attributes=False))
    assert len(differences) == 2


# ---- the requests a run makes are counted from httpx's own log ---------------------------

def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord("httpx", logging.INFO, __file__, 1, message, None, None)


def test_the_request_counter_counts_only_requests_to_the_hosts_it_was_given() -> None:
    counter = RequestCounter(["Node.Example", "tnl.ebsi.eu"])
    for line in (
        'HTTP Request: GET https://node.example/v1/alive "HTTP/1.1 200 OK"',
        'HTTP Request: GET https://node.example:443/v1/alive "HTTP/1.1 503 Service Unavailable"',
        'HTTP Request: GET https://TNL.EBSI.EU/tnl.json "HTTP/1.1 200 OK"',
        'HTTP Request: GET https://other.example/v1/alive "HTTP/1.1 200 OK"',
        'HTTP Request: GET https://node.example.evil.example/x "HTTP/1.1 200 OK"',
        'HTTP Request: GET https://node.example:8443/x "HTTP/1.1 200 OK"',
        'HTTP Request: GET http://node.example/x "HTTP/1.1 200 OK"',
        "Starting new connection to node.example",
        "",
    ):
        counter.emit(_record(line))
    assert counter.counts == {"node.example": 2, "tnl.ebsi.eu": 1}


def test_the_request_counter_counts_what_a_real_client_sends(
        monkeypatch: pytest.MonkeyPatch) -> None:
    real = httpx.Client
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(str(request.url))
        return httpx.Response(503) if len(hits) == 1 else httpx.Response(200, json={"a": 1})

    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    client = EbsiHttpClient(
        allowed_hosts={"node.example"},
        retry=RetryPolicy(attempts=3, backoff_base_s=0.0, backoff_max_s=0.0))
    with count_requests(["node.example"]) as counts:
        assert client.get_json("https://node.example/v1/alive") == {"a": 1}
    client.close()
    assert len(hits) == 2 and counts == {"node.example": 2}      # the retry is counted
    assert not any(isinstance(h, RequestCounter) for h in logging.getLogger("httpx").handlers)


def test_count_requests_restores_the_logger_level() -> None:
    logger = logging.getLogger("httpx")
    before = logger.level
    with count_requests(["node.example"]):
        assert logger.isEnabledFor(logging.INFO)
    assert logger.level == before


# ---- the step summary shows validated values only ----------------------------------------

def _fixture_result(now: datetime = NOW) -> VerifiedNodeList:
    return verify_chain(fixture_chain(), now=now)


def test_the_tnl_summary_is_built_from_validated_values() -> None:
    result = _fixture_result()
    text = render_tnl_summary(
        result=result, now=NOW, threshold=2, warn_days=14,
        keylist_key_sha256=RECORDED_KEYLIST_KEY_SHA256,
        requests=Counter({"tnl.ebsi.eu": 5}), findings=[])
    for needle in (f"tnl.json version | {FIXTURE_LIST_VERSION} (last seen {LAST_SEEN_TNL_VERSION};"
                   f" shipped floor {LIST_VERSION_FLOOR}, lag"
                   f" {LAST_SEEN_TNL_VERSION - LIST_VERSION_FLOOR})",
                   "2026-10-06T13:33:18Z", "2027-01-04T13:33:18Z", "days left | 80 (warning at 14)",
                   f"trusted-keys.json version | {FIXTURE_KEYS_VERSION} (last seen"
                   f" {LAST_SEEN_KEYS_VERSION}; shipped floor {KEYS_VERSION_FLOOR}, lag"
                   f" {LAST_SEEN_KEYS_VERSION - KEYS_VERSION_FLOOR})",
                   "custodian threshold | 2", "the recorded file", "tnl.ebsi.eu: 5",
                   "**Findings:** none"):
        assert needle in text, needle


def test_the_tnl_summary_lists_each_finding_by_code_only() -> None:
    result = _fixture_result()
    findings = _findings(now=EXPIRES, keylist_key_sha256=H2)
    text = render_tnl_summary(
        result=result, now=EXPIRES - timedelta(days=3), threshold=2, warn_days=14,
        keylist_key_sha256=H2, requests=Counter(), findings=findings)
    assert "- `EXPIRING`" in text and "- `ANCHOR_FILE`" in text
    assert "NOT the recorded file" in text and "days left | 3 " in text
    assert "look for a reissue" not in text            # the actions go to the failure, not here


def test_the_tnl_summary_says_expired_for_a_clock_past_expires() -> None:
    text = render_tnl_summary(
        result=_fixture_result(), now=EXPIRES + SECOND, threshold=2, warn_days=14,
        keylist_key_sha256=H1, requests=Counter(), findings=[])
    assert "days left | expired (warning at 14)" in text


HOSTILE = [
    "evil | row\n| x", "<script>alert(1)</script>", "`code`", "[l](https://e.example)",
    "a" * 201, "‮", "tab\there", "x\r\ny", "![i](https://e.example/i.png)", 1.5, None,
    b"bytes", ["a"], True,
]


@pytest.mark.parametrize("value", HOSTILE, ids=repr)
def test_a_cell_never_shows_what_could_break_the_table_or_the_page(value: object) -> None:
    assert _cell(value) == "(not shown)"


def test_a_cell_shows_ints_instants_and_plain_ascii() -> None:
    assert _cell(7) == "7"
    assert _cell(NOW) == "2026-10-16T12:00:00Z"
    assert _cell("api-preprod.ebsi.grnet.gr") == "api-preprod.ebsi.grnet.gr"
    assert _cell("HttpTransientExhausted") == "HttpTransientExhausted"
    assert _cell(datetime(2026, 1, 1)) == "(not shown)"           # naive: not from the verifier


def test_the_core_summary_shows_hosts_outcomes_and_request_counts() -> None:
    selection = Selection(
        chosen=(_node(1), _node(2)),
        failures=(NodeFailure("down.example", "HttpError", 403),
                  NodeFailure("slow.example", "HttpTransientExhausted", None)),
        skipped=("dup.example",))
    text = render_core_summary(
        did=DEFAULT_CORE_DID, selection=selection,
        reads=[(_node(1).host, "read ok"), (_node(2).host, "read ok")],
        requests=Counter({_node(1).host: 6, _node(2).host: 6, "down.example": 3}),
        differences=[])
    assert f"| {_node(1).host} | read ok | 6 |" in text
    assert "| down.example | not used: HttpError 403 | 3 |" in text
    assert "| slow.example | not used: HttpTransientExhausted | 0 |" in text
    assert "same operator as a chosen node): 1" in text
    assert "**Differences between the two nodes:** none" in text
    assert DEFAULT_CORE_DID in text


def test_the_core_summary_cannot_be_made_to_carry_a_hostile_string() -> None:
    selection = Selection((), (NodeFailure("a|b\n<x>", "Err`or", 7),), ())
    text = render_core_summary(
        did="did:ebsi:z\n# injected", selection=selection,
        reads=[("h|ost", "<b>ok</b>")], requests=Counter(), differences=["x\n## injected"])
    # the DID, the failure's host and kind, the read's host and outcome, the difference
    assert text.count("(not shown)") == 6
    assert [line for line in text.splitlines() if line.startswith("#")] == [
        "### Core v1 preprod smoke"]
    assert not any(bad in text for bad in ("<", "injected", "ost", "`or"))


def test_the_step_summary_is_appended_where_the_runner_says_and_nowhere_else(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "summary.md"
    target.write_text("earlier\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))
    write_step_summary("one")
    write_step_summary("two")
    assert target.read_text() == "earlier\none\ntwo\n"
    monkeypatch.delenv("GITHUB_STEP_SUMMARY")
    write_step_summary("three")                    # no variable: a no-op
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", "")
    write_step_summary("four")                     # an empty one too
    assert target.read_text() == "earlier\none\ntwo\n"


def test_only_the_two_live_tests_read_the_wall_clock() -> None:
    # the recorded list expires 2027-01-04: an offline test that read the clock would go red
    # that day. The clock is read inside a live test, never at import and never in a helper.
    tree = ast.parse(Path(__file__).read_text())
    readers = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in ("now", "utcnow", "today", "time") for call in ast.walk(node))
    }
    assert readers == {"test_live_core_v1_preprod", "test_live_tnl_watch"}
    module_level = [stmt for stmt in tree.body if not isinstance(
        stmt, (ast.FunctionDef, ast.ClassDef))]
    assert not any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                   and call.func.attr in ("now", "utcnow", "today")
                   for stmt in module_level for call in ast.walk(stmt))


def test_only_the_two_live_tests_write_a_step_summary() -> None:
    tree = ast.parse(Path(__file__).read_text())
    writers = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id == "write_step_summary" for call in ast.walk(node))
    } - {"write_step_summary"}
    # the unit test of the writer itself points GITHUB_STEP_SUMMARY at a temporary file
    assert writers == {
        "test_live_core_v1_preprod", "test_live_tnl_watch",
        "test_the_step_summary_is_appended_where_the_runner_says_and_nowhere_else"}


# ---- the real chain of #319, through the real verifier, with the clock fixed -------------

def test_the_recorded_key_file_is_the_shipped_anchor() -> None:
    block = (TNL_FIXTURES / "keylist-key.asc").read_bytes()
    assert Anchor.from_public_key_block(block) == EUROPEUM_KEY_LIST_ANCHOR
    assert RECORDED_KEYLIST_KEY_SHA256 == (
        "a222771cb519abd48df677519caa7c3614219b9a15885c6ca232ad05f65908e5")


def test_the_recorded_chain_with_last_seen_equal_to_its_versions_has_no_findings() -> None:
    chain = fixture_chain()
    result = verify_chain(chain, now=NOW)
    assert (result.version, result.accepted_keys.version) == (
        FIXTURE_LIST_VERSION, FIXTURE_KEYS_VERSION)
    assert tnl_watch_findings(
        now=NOW, expires=result.expires, list_version=result.version,
        keys_version=result.accepted_keys.version, keylist_key_sha256=_sha256(chain.keylist_key),
        warn_days=14, last_seen_list=FIXTURE_LIST_VERSION, last_seen_keys=FIXTURE_KEYS_VERSION,
        recorded_keylist_key_sha256=RECORDED_KEYLIST_KEY_SHA256) == []


def test_the_recorded_chain_warns_at_exactly_fourteen_days_and_not_a_second_before() -> None:
    chain = fixture_chain()
    result = verify_chain(chain, now=NOW)
    mark = result.expires - timedelta(days=14)
    kwargs: dict[str, Any] = dict(
        expires=result.expires, list_version=result.version,
        keys_version=result.accepted_keys.version, keylist_key_sha256=_sha256(chain.keylist_key),
        warn_days=14, last_seen_list=result.version, last_seen_keys=result.accepted_keys.version,
        recorded_keylist_key_sha256=RECORDED_KEYLIST_KEY_SHA256)
    assert _codes(tnl_watch_findings(now=mark, **kwargs)) == ["EXPIRING"]
    assert tnl_watch_findings(now=mark - SECOND, **kwargs) == []
    # and the verifier itself accepts the list at both instants
    assert verify_chain(chain, now=mark).expires == result.expires
    assert verify_chain(chain, now=mark - SECOND).expires == result.expires


@pytest.mark.parametrize("offset", [timedelta(0), SECOND, timedelta(days=30)], ids=repr)
def test_the_recorded_chain_past_its_expiry_is_the_verifiers_expiry_class(
        offset: timedelta) -> None:
    with pytest.raises(NodeListExpired) as caught:
        verify_chain(fixture_chain(), now=EXPIRES + offset)
    assert type(caught.value) is NodeListExpired


def test_the_watch_reads_the_key_list_own_version_and_the_served_key_file() -> None:
    chain = fixture_chain()
    result = verify_chain(chain, now=NOW)
    seen = dict(last_seen_list=FIXTURE_LIST_VERSION, last_seen_keys=FIXTURE_KEYS_VERSION)
    assert watch(result, chain, now=NOW, warn_days=14, **seen) == []
    # tnl.json's keysVersion is not the rotation signal: only trusted-keys.json's own version is
    moved = dataclasses.replace(result, keys_version=7)
    assert watch(moved, chain, now=NOW, warn_days=14, **seen) == []
    rotated = dataclasses.replace(
        result, accepted_keys=Accepted(FIXTURE_KEYS_VERSION + 1, "0" * 64))
    assert _codes(watch(rotated, chain, now=NOW, warn_days=14, **seen)) == ["KEYS_VERSION"]
    swapped = dataclasses.replace(chain, keylist_key=chain.keylist_key + b"\n")
    assert _codes(watch(result, swapped, now=NOW, warn_days=14, **seen)) == ["ANCHOR_FILE"]
    older = dataclasses.replace(result, expires=NOW + timedelta(days=14))
    assert _codes(watch(older, chain, now=NOW, warn_days=14, **seen)) == ["EXPIRING"]


def test_the_watch_defaults_to_the_last_seen_constants() -> None:
    chain = fixture_chain()
    # a result AT the last-seen versions (the constants move; the fixture stays where it was)
    at_last_seen = dataclasses.replace(
        verify_chain(chain, now=NOW), version=LAST_SEEN_TNL_VERSION,
        accepted_keys=Accepted(LAST_SEEN_KEYS_VERSION, "0" * 64))
    assert watch(at_last_seen, chain, now=NOW, warn_days=14) == []
    moved = dataclasses.replace(at_last_seen, version=LAST_SEEN_TNL_VERSION + 1)
    assert _codes(watch(moved, chain, now=NOW, warn_days=14)) == ["LIST_VERSION"]
    rotated = dataclasses.replace(
        at_last_seen, accepted_keys=Accepted(LAST_SEEN_KEYS_VERSION + 1, "0" * 64))
    assert _codes(watch(rotated, chain, now=NOW, warn_days=14)) == ["KEYS_VERSION"]


def test_the_recorded_chain_is_verified_as_the_stateless_caller() -> None:
    # the source of the verification the live tests make, read as text: no stored state, no
    # max_age, the shipped anchor and floors (no override passed)
    source = inspect.getsource(verify_chain)
    assert "last_accepted_list=None" in source and "last_accepted_keys=None" in source
    for override in ("anchor", "list_floor", "keys_floor", "max_age", "min_threshold"):
        assert f"{override}=" not in source


def test_the_recorded_chain_names_preprod_nodes_with_distinct_operators() -> None:
    nodes = _fixture_result().nodes
    assert len(nodes) >= WANT_NODES
    assert all(node.host.startswith("api-preprod.ebsi.") for node in nodes)
    assert len({node.organisation for node in nodes}) >= WANT_NODES


# ---- invariants: a release cannot ship a floor nobody has seen live ----------------------

def test_the_shipped_floors_never_exceed_what_was_last_seen_live() -> None:
    assert LIST_VERSION_FLOOR <= LAST_SEEN_TNL_VERSION
    assert KEYS_VERSION_FLOOR <= LAST_SEEN_KEYS_VERSION


def test_last_seen_is_never_below_the_recorded_fixture() -> None:
    result = _fixture_result()
    assert LAST_SEEN_TNL_VERSION >= result.version
    assert LAST_SEEN_KEYS_VERSION >= result.accepted_keys.version


def test_last_seen_constants_are_plain_ints() -> None:
    assert type(LAST_SEEN_TNL_VERSION) is int and type(LAST_SEEN_KEYS_VERSION) is int


# ---- the whole core-v1 flow, offline: real clients, recorded bodies of two real nodes ------

NODE_GRNET = Node("https://api-preprod.ebsi.grnet.gr", "api-preprod.ebsi.grnet.gr", "GR", "GRNET")
NODE_INCM = Node("https://api-preprod.ebsi.incm.pt", "api-preprod.ebsi.incm.pt", "PT", "INCM")
NODE_DOWN = Node("https://api-preprod.ebsi.down.example", "api-preprod.ebsi.down.example",
                 "PT", "Down")
NODE_DEAD = Node("https://api-preprod.ebsi.dead.example", "api-preprod.ebsi.dead.example",
                 "PT", "Dead")
NODE_404 = Node("https://api-preprod.ebsi.old.example", "api-preprod.ebsi.old.example",
                "PT", "Old")


def _recorded_routes() -> dict[str, bytes]:
    manifest = json.loads((CORE_FIXTURES / "MANIFEST.json").read_bytes())
    routes = {}
    for rel, entry in manifest["files"].items():
        if rel.split("/")[0] in ("preprod-grnet", "preprod-incm") and "?" not in entry[
                "request_url"] and not rel.endswith("issuers_page.json"):
            routes[entry["request_url"]] = (CORE_FIXTURES / rel).read_bytes()
    return routes


def _transport(monkeypatch: pytest.MonkeyPatch,
               tweak: dict[str, Callable[[bytes], bytes]] | None = None,
               drop: Callable[[str], bool] | None = None) -> list[str]:
    """Patch ``httpx.Client`` so every EbsiHttpClient built afterwards serves the recorded
    bodies of the two preprod nodes (plus ``/v1/alive``) and the recorded list chain on
    ``tnl.ebsi.eu``. ``tweak`` edits a body by URL
    substring, ``drop`` removes the routes it matches (a 404), and a third node answers 403
    with an HTML page."""
    routes = {url: body for url, body in _recorded_routes().items()
              if not (drop is not None and drop(url))}
    for name in ("tnl.json", "tnl.json.sig", "trusted-keys.json", "trusted-keys.json.sig",
                 "keylist-key.asc"):                        # the list host: the recorded chain
        routes[f"https://{TNL_HOST}/{name}"] = (TNL_FIXTURES / name).read_bytes()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if url.startswith(NODE_DEAD.origin):
            raise httpx.ConnectTimeout("timed out", request=request)
        if url.startswith(NODE_404.origin):          # a node with no /v1/alive route at all
            return httpx.Response(404, json={"type": "about:blank"},
                                  headers={"content-type": "application/problem+json"})
        if url.startswith(NODE_DOWN.origin):
            return httpx.Response(
                403, text="<html><title>Web Application Firewall</title></html>",
                headers={"content-type": "text/html"})
        if url.endswith("/v1/alive"):
            return httpx.Response(200, json={"health_global": 1})
        body = routes.get(url)
        if body is None:
            return httpx.Response(404, json={"type": "urn:ebsi:problems:identifier-not-found"},
                                  headers={"content-type": "application/problem+json"})
        for needle, edit in (tweak or {}).items():
            if needle in url:
                body = edit(body)
        # a body as a socket delivers it: the bytes path reads it raw (iter_raw), which a
        # response built with content= has already consumed
        return httpx.Response(200, stream=httpx.ByteStream(body),
                              headers={"content-type": "application/json"})

    real = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return seen


def _run(nodes: Sequence[Node], did: str = DEFAULT_CORE_DID) -> CoreRun:
    run = CoreRun()
    run_core_v1(run, nodes, did)
    return run


def test_the_recorded_bodies_of_two_preprod_nodes_agree_through_real_clients(
        monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _transport(monkeypatch)
    run = _run([NODE_DOWN, NODE_GRNET, NODE_INCM])
    assert run.selection is not None
    assert [n.host for n in run.selection.chosen] == [NODE_GRNET.host, NODE_INCM.host]
    assert run.selection.failures == (NodeFailure(NODE_DOWN.host, "HttpError", 403),)
    assert run.differences == [] and len(run.observations) == 2
    first = run.observations[0]
    assert first.did_id == DEFAULT_CORE_DID and first.has_attributes
    assert len(first.methods) == 2 and len(first.accreditations) == 1
    assert run.reads == [(NODE_GRNET.host, "read ok"), (NODE_INCM.host, "read ok")]
    # a 403 probe, then per node /v1/alive + the DID document, the issuer, its attribute list
    # and the one attribute: the request count the live summary reports
    assert run.counts == {NODE_DOWN.host: 1, NODE_GRNET.host: 5, NODE_INCM.host: 5}
    assert len(seen) == 11


def test_fetch_chain_makes_five_gets_to_the_list_host_alone_and_returns_the_bytes_as_served(
        monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _transport(monkeypatch)
    chain, counts = fetch_chain()
    assert chain == fixture_chain()
    assert seen == [f"https://{TNL_HOST}/{name}" for name in (
        "trusted-keys.json", "trusted-keys.json.sig", "tnl.json", "tnl.json.sig",
        "keylist-key.asc")]
    assert counts == {TNL_HOST: 5}
    assert verify_chain(chain, now=NOW).version == FIXTURE_LIST_VERSION


def test_fetch_chain_refuses_a_key_file_over_its_cap_and_an_answer_that_is_not_a_200(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _transport(monkeypatch, tweak={"keylist-key.asc": lambda b: b + b"x" * KEYLIST_KEY_MAX_BYTES})
    with pytest.raises(HttpError) as caught:
        fetch_chain()
    assert type(caught.value) is HttpError and "exceeds" in str(caught.value)


@pytest.mark.parametrize("name", ["tnl.json", "keylist-key.asc"])
def test_fetch_chain_does_not_follow_a_redirect_away_from_the_list_host(
        monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    seen = _transport(monkeypatch)
    inner = httpx.Client

    def redirecting(**kw: Any) -> Any:
        client = inner(**kw)
        real_send = client.send

        def send(request: httpx.Request, **options: Any) -> httpx.Response:
            if request.url.path.endswith(name):
                return httpx.Response(302, headers={"location": "https://evil.example/x"},
                                      request=request)
            return real_send(request, **options)
        client.send = send                                  # type: ignore[method-assign]
        return client

    monkeypatch.setattr(httpx, "Client", redirecting)
    with pytest.raises(HttpError) as caught:
        fetch_chain()
    assert type(caught.value) is HttpError and "302" in str(caught.value)
    assert not any("evil.example" in url for url in seen)


def test_the_offline_suite_refuses_a_socket_and_a_name_lookup() -> None:
    with pytest.raises(AssertionError):
        socket.socket().connect(("127.0.0.1", 9))
    with pytest.raises(AssertionError):
        socket.getaddrinfo("example.invalid", 443)
    with pytest.raises(AssertionError):
        socket.create_connection(("example.invalid", 443))


def test_a_node_that_does_not_answer_costs_one_attempt_and_the_run_goes_on(
        monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _transport(monkeypatch)
    run = _run([NODE_DEAD, NODE_404, NODE_GRNET, NODE_INCM])
    assert run.selection is not None
    assert run.selection.failures == (
        NodeFailure(NODE_DEAD.host, "HttpTransientExhausted", None),
        NodeFailure(NODE_404.host, "HttpNotFound", 404))
    assert seen.count(f"{NODE_DEAD.origin}/v1/alive") == 1          # not three
    assert run.differences == []


def test_fewer_than_two_usable_nodes_stops_before_any_read(
        monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _transport(monkeypatch)
    run = _run([NODE_DOWN, NODE_DEAD, NODE_GRNET])
    assert run.selection is not None and run.observations == []
    assert run.reads == [(NODE_GRNET.host, "alive, not read")]
    assert len(seen) == 3                                       # three probes, nothing read
    message = too_few_nodes_message(run.selection)
    assert message.endswith(
        f"1 found; failures: {NODE_DOWN.host}: HttpError 403; "
        f"{NODE_DEAD.host}: HttpTransientExhausted")
    assert "Firewall" not in message


@pytest.mark.parametrize("needle,edit,label", [
    ("incm.pt/v1/did-registry", lambda b: b.replace(b'"secp256k1"', b'"secp256k2"'),
     "verification methods"),
    ("incm.pt/v1/issuers-registry/issuers/did:ebsi:zmaEptEHQRAmkJnFV6ki3io/attributes/",
     lambda b: b.replace(b'"RootTAO"', b'"TAO"'), "issuer record accreditations"),
], ids=["a-key-differs", "an-accreditation-differs"])
def test_a_node_that_serves_other_content_is_reported_by_field(
        monkeypatch: pytest.MonkeyPatch, needle: str, edit: Callable[[bytes], bytes],
        label: str) -> None:
    _transport(monkeypatch, tweak={needle: edit})
    run = _run([NODE_GRNET, NODE_INCM])
    assert len(run.differences) == 1 and run.differences[0].startswith(label)
    summary = render_core_summary(
        did=DEFAULT_CORE_DID, selection=run.selection, reads=run.reads, requests=run.counts,
        differences=run.differences)
    assert f"- {run.differences[0]}" in summary
    assert f"{NODE_GRNET.host} and {NODE_INCM.host} differ" in run.differences[0]


def test_a_node_whose_record_says_attributes_but_lists_none_fails_the_read(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _transport(monkeypatch, tweak={"/attributes": lambda b: b.replace(b'"items"', b'"things"')})
    run = CoreRun()
    with pytest.raises(AssertionError, match="hasAttributes, but the walk found none"):
        run_core_v1(run, [NODE_GRNET, NODE_INCM], DEFAULT_CORE_DID)
    assert run.reads == [(NODE_GRNET.host, "read failed: AssertionError")]
    assert "read failed: AssertionError" in render_core_summary(
        did=DEFAULT_CORE_DID, selection=run.selection, reads=run.reads, requests=run.counts,
        differences=[])


def test_a_document_for_another_did_fails_the_read_with_the_resolvers_class(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _transport(monkeypatch, tweak={"/did-registry/": lambda b: b.replace(
        b"zmaEptEHQRAmkJnFV6ki3io", b"zZeKyEJfUTGwajhNyNX928z")})
    with pytest.raises(DidResolutionError):
        _run([NODE_GRNET, NODE_INCM])


def test_a_second_node_with_a_missing_record_is_a_read_failure_not_a_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _transport(monkeypatch, drop=lambda url: url.startswith(NODE_INCM.origin)
               and "/issuers-registry/issuers/" in url)
    run = CoreRun()
    with pytest.raises(HttpNotFound):
        run_core_v1(run, [NODE_GRNET, NODE_INCM], DEFAULT_CORE_DID)
    assert run.reads == [
        (NODE_GRNET.host, "read ok"), (NODE_INCM.host, "read failed: HttpNotFound")]


# ---- the live tests are opt-in, and the workflow can select them by name -----------------

LIVE_TESTS = {"test_live_core_v1_preprod": "live_core_v1", "test_live_tnl_watch": "live_tnl_watch"}


@pytest.mark.parametrize("name", sorted(LIVE_TESTS), ids=["core-v1-smoke", "watch"])
def test_each_live_test_is_skipped_unless_the_opt_in_variable_is_one(name: str) -> None:
    marks = [m for m in globals()[name].pytestmark if m.name == "skipif"]
    assert len(marks) == 1
    assert marks[0].args == (os.getenv("OPENVC_EBSI_LIVE") != "1",)
    assert marks[0].kwargs["reason"] == "live EBSI test is opt-in"


def _candidate_ids(mark: Any) -> list[str]:
    """The text a parametrize mark can put in a test id: its explicit ids (called, when they
    are a function) or, failing that, its values."""
    values = [v.values if hasattr(v, "values") else (v,) for v in mark.args[1]]
    flat = [item for row in values for item in (row if isinstance(row, tuple) else (row,))]
    ids = mark.kwargs.get("ids")
    if isinstance(ids, (list, tuple)):
        return [str(i) for i in ids]
    if callable(ids):
        return [str(ids(item)) for item in flat]
    return [str(item) for item in flat]


def test_the_workflow_selector_matches_the_two_live_tests_and_nothing_else() -> None:
    # `-k live_core_v1` / `-k live_tnl_watch` match a test's name and its parametrize id
    selectors = set(LIVE_TESTS.values())
    for name, test in list(globals().items()):
        if not (name.startswith("test_") and callable(test)):
            continue
        texts = [name] + [i for m in getattr(test, "pytestmark", []) if m.name == "parametrize"
                          for i in _candidate_ids(m)]
        hits = {sel for sel in selectors if any(sel in text for text in texts)}
        assert hits == ({LIVE_TESTS[name]} if name in LIVE_TESTS else set()), name


# ---- the workflow file: what a reviewer cannot see in a green pytest run -----------------

WORKFLOW = HERE.parent / ".github" / "workflows" / "live-ebsi.yml"


def _workflow() -> str:
    if not WORKFLOW.exists():            # a source tree without .github (an sdist)
        pytest.skip("the workflow file is not in this tree")
    return WORKFLOW.read_text(encoding="utf-8")


def test_the_workflow_runs_on_a_schedule_and_on_demand_never_on_a_pull_request() -> None:
    text = _workflow()
    on_block = re.search(r"^on:\n((?:[ ]+.*\n|\n)+)", text, re.M)
    assert on_block is not None
    triggers = re.findall(r"^  ([a-z_]+):", on_block.group(1), re.M)
    assert triggers == ["schedule", "workflow_dispatch"]
    assert re.search(r"^permissions:\n  contents: read\n(?!  )", text, re.M)
    assert "write" not in re.sub(r"#.*", "", text)


def test_the_workflow_has_one_job_per_lane_and_selects_the_live_tests_by_name() -> None:
    text = _workflow()
    assert re.findall(r"^  ([a-z0-9-]+):\n    name:", text, re.M) == [
        "live", "core-v1", "tnl-watch"]
    commands = re.findall(r"^        run: (pytest .*)$", text, re.M)
    assert commands == [
        "pytest -q tests/test_ebsi_verifier.py -k live",
        "pytest -q -rs tests/test_ebsi_live.py -k live_core_v1",
        "pytest -q -rs tests/test_ebsi_live.py -k live_tnl_watch"]
    assert {cmd.rsplit(" ", 1)[1] for cmd in commands[1:]} == set(LIVE_TESTS.values())
    assert text.count('OPENVC_EBSI_LIVE: "1"') == 3


def test_the_daily_schedule_runs_the_watch_alone_and_monday_runs_everything() -> None:
    text = _workflow()
    crons = re.findall(r'^    - cron: "([^"]+)"', text, re.M)
    assert crons == ["17 6 * * 1", "17 6 * * 0,2-6"]        # Monday; every other day, once each
    gates = re.findall(r"^    if: (.*)$", text, re.M)
    assert gates == [f"github.event_name == 'workflow_dispatch' || "
                     f"github.event.schedule == '{crons[0]}'"] * 2
    jobs = re.split(r"^  (?=[a-z0-9-]+:\n    name:)", text, flags=re.M)
    watch_job = next(job for job in jobs if job.startswith("tnl-watch:"))
    assert "    if:" not in watch_job                          # it runs on both entries


def test_the_warn_days_input_reaches_the_test_through_the_environment_only() -> None:
    text = _workflow()
    for line in text.splitlines():             # an expression is a gate or that one env value
        if "${{" in line:
            assert re.match(r"^\s+(if|OPENVC_TNL_WARN_DAYS): ", line), line
    assert "          OPENVC_TNL_WARN_DAYS: ${{ inputs.warn_days || '14' }}" in text
    assert re.search(r'^      warn_days:\n(?:        .*\n)*?        default: "14"$', text, re.M)
