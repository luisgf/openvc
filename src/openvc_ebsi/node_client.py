"""
openvc_ebsi.node_client — a client bound to a verified Trusted Nodes List, with single-node
failover (ADR-0009 D5, issue #324).

:func:`~openvc_ebsi.nodes.verify_node_list` answers "which nodes are approved, until when". This
module turns that answer into something a service can keep using::

    result = verify_node_list(..., environment="prod", now=now, ...)      # offline, once
    with for_nodes(result, clock=lambda: datetime.now(timezone.utc),
                   decode_jwt=suite.peek_claims) as nodes:
        badge = nodes.run(
            lambda s: verify_ebsi_badge(token, resolver=s.resolver, proof_suite=suite))

What it adds to a hand-built allow-list (ADR-0009 D1):

  * **The list's lifetime travels with the client.** The allow-list is exactly the result's
    hosts, the client carries the result's ``expires`` and an injected wall ``clock``, and at or
    after that instant every read raises :class:`~openvc_ebsi.errors.NodeListExpired` before the
    cache is consulted and before a socket is opened. Without this the verifier's expiry check is
    a one-time gate and a service that verifies once trusts that node set indefinitely. There is
    no grace and no refresh: rebuild the client from a freshly verified list before ``expires``.
  * **One environment, one client.** There is no ``extra_hosts``, no ``allowed_hosts`` and no
    merge of two results. The environment label is the verifier's, never ``EBSI_HOSTS``'.
  * **Single-node walks.** A registry walk (an ``issuer_record``, a ``verify_trust_chain``, a
    ``verify_ebsi_badge``) runs on ONE node from start to end. When that node fails, the whole
    walk restarts on the next candidate; nodes are never mixed inside a walk, because ``self``
    and ``links`` URLs carry the answering node's own host and a node is not known to agree
    with another. A session refuses (``HttpForbiddenHost``, before any socket) a URL that is not
    on its node, whatever the adapter does with a body link.
  * **A health check and an injected node choice.** ``GET /v1/alive`` (one attempt, status
    aware, memoised for ``health_ttl_s``) and a ``policy`` that orders the candidates (default:
    random). A policy's output is untrusted: a name that is not in the result is refused.

**What fails over and what does not** (one table, :data:`_FAILOVER`, independent of the API
version): a transport error or timeout, a 429 or a 5xx once retries are used up, a 403 (a node's
firewall may refuse a client on its User-Agent), a 3xx (redirects are never followed), a body
past the size cap or the deadline, and a failed ``/v1/alive`` move on to the next node. A node
that *answers* does not: a 404 is that node's answer (it is :class:`~openvc_ebsi.http.HttpNotFound`
naming the node, and a lagging node can say it for a brand-new DID), and so is any other 4xx, a
malformed 200, and every error that is about the content rather than the node
(``AccreditationInvalid``, ``NoTrustedAnchor``, ``IssuerNotTrusted`` ...). Cross-node agreement
is not built (ADR-0009 open question 5).

**What it does not give** (ADR-0009 D7): the list authenticates the *operator* of each node, not
the *content* it serves. A dishonest listed node can serve another key for a DID, and openvc will
verify what it is given.

Nothing here persists anything or runs anything in the background; the only state is a small
in-memory health verdict per node and the client's response cache.
"""
from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import Any, Literal, TypeVar, cast, get_args

from openvc import __version__, _json
from openvc.cache import TtlCache
from openvc.observability import logger
from openvc.proof._verify_common import safe_repr

from ._message import bounded_text, url_repr
from .errors import EbsiError, NodeClientConfigError, NodeListError, NodeListExpired
from .http import (
    MAX_RESPONSE_BYTES,
    AddressGuard,
    EbsiHttpClient,
    HttpError,
    HttpForbiddenAddress,
    HttpForbiddenHost,
    HttpTransientExhausted,
    RetryPolicy,
    _as_utc,
    read_clock,
)
from .nodes import MAX_NODES, Node, VerifiedNodeList, check_node_origin
from .versioning import (
    DecodeJwt,
    DidEbsiResolver,
    _on_origin,
    _origin,
    did_registry_adapter,
    tir_adapter,
)

__all__ = [
    "EbsiNodeClient", "FAILURE_KINDS", "NODE_RETRY", "NoHealthyNode", "NodeClientConfigError",
    "NodeFailure", "NodeFailureKind", "NodePolicy", "NodeSession", "classify", "for_nodes",
    "random_order",
]

T = TypeVar("T")

NodeFailureKind = Literal[
    "unreachable", "unavailable", "forbidden", "redirect", "limits", "unhealthy"]
#: The closed set of reasons a node is passed over.
FAILURE_KINDS: tuple[str, ...] = get_args(NodeFailureKind)

#: Orders the candidate origins to try: ``policy(origins)`` returns the order. **Its output is
#: untrusted**: every item must be one of *origins* (the exact string), at most once, and there
#: must be at least one, or the call is a :class:`~openvc_ebsi.errors.NodeClientConfigError`.
NodePolicy = Callable[[tuple[str, ...]], Iterable[str]]

#: The health probe, relative to a node's origin (EBSI Core API v1, ADR-0009).
ALIVE_PATH = "/v1/alive"

#: The retry policy ``for_nodes`` uses when none is passed: one retry, not two. With another node
#: to fail over to, a second retry buys little and costs a dead node ``timeout_s`` more; the
#: measured worst case is in the CHANGELOG. ``for_ebsi``'s default is unchanged.
NODE_RETRY = RetryPolicy(attempts=2)

_DEFAULT_ADDRESS_GUARD = AddressGuard()


def random_order(origins: tuple[str, ...]) -> list[str]:
    """The default policy: every candidate once, in random order."""
    order = list(origins)
    random.shuffle(order)
    return order


# --------------------------------------------------------------------------- #
# Failures and their classification
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class NodeFailure:
    """Why one node was passed over: its ``origin``, a ``kind`` from :data:`FAILURE_KINDS` and
    the HTTP ``status`` when there was one. **Nothing else, on purpose**: never a response
    body, a header value, a ``Location`` or an exception message, so a hostile node cannot put
    text into a log line or into the :class:`NoHealthyNode` that lists its failure."""

    origin: str
    kind: NodeFailureKind
    status: int | None = None


class NoHealthyNode(EbsiError):
    """Every candidate was examined (or skipped as known-bad) and none could run the walk.
    ``failures`` holds one :class:`NodeFailure` per candidate, in the order they were
    examined. A node beyond ``max_nodes`` was never contacted and is not listed."""

    def __init__(self, failures: tuple[NodeFailure, ...]) -> None:
        self.failures = failures
        kinds: dict[str, int] = {}
        for failure in failures:
            kinds[failure.kind] = kinds.get(failure.kind, 0) + 1
        detail = ", ".join(f"{count} {kind}" for kind, count in kinds.items()) or "none examined"
        super().__init__(f"no healthy node among {len(failures)} examined ({detail})")

    def __reduce__(self) -> tuple[Any, ...]:
        return (type(self), (self.failures,))


def _is_plain_http_error(exc: BaseException) -> bool:
    # The exact class: HttpNotFound, HttpForbiddenHost, HttpTransientExhausted and
    # HttpUnexpectedEncoding are subclasses with their own meaning and their own rows.
    return type(exc) is HttpError


def _status(exc: BaseException) -> int | None:
    status = getattr(exc, "status", None)
    return status if type(status) is int else None


def _in_status(low: int, high: int) -> Callable[[BaseException], bool]:
    return lambda exc: _is_plain_http_error(exc) and low <= (_status(exc) or 0) < high


# The one table. First match wins. Written against the shipped error shapes of ``http.py``:
# the size cap is ``HttpError(status=200)``, the deadline is ``HttpError(status=None)``, a 403
# or a 3xx is ``HttpError(status=...)``, and ``HttpTransientExhausted.status`` is ``None`` for
# a transport failure and the last 429 / 5xx otherwise. A body is never consulted.
_FAILOVER: tuple[tuple[Callable[[BaseException], bool], NodeFailureKind], ...] = (
    # a listed name that resolves to an address the guard refuses: this node cannot be reached
    # safely, another can (a default pending confirmation; the other option propagates it)
    (lambda exc: isinstance(exc, HttpForbiddenAddress), "unreachable"),
    # transport error, timeout, unresolvable name: retries used up without an answer
    (lambda exc: isinstance(exc, HttpTransientExhausted) and _status(exc) is None, "unreachable"),
    # 429 / 5xx, retries used up
    (lambda exc: isinstance(exc, HttpTransientExhausted), "unavailable"),
    # a 5xx or 429 the policy did not retry
    (lambda exc: _is_plain_http_error(exc) and (_status(exc) == 429 or (_status(exc) or 0) >= 500),
     "unavailable"),
    # a firewall's 403 (ADR-0009: api.ebsi.stsisp.ro refused curl's default User-Agent)
    (lambda exc: _is_plain_http_error(exc) and _status(exc) == 403, "forbidden"),
    # redirects are never followed
    (_in_status(300, 400), "redirect"),
    # a body past the cap (200) or the read deadline (no status)
    (lambda exc: _is_plain_http_error(exc) and _status(exc) in (None, 200), "limits"),
)


def classify(exc: BaseException) -> NodeFailureKind | None:
    """The kind of node failure *exc* is, or ``None`` when it is not one: a 404 (that node's
    answer), any other 4xx, a malformed 200, a refusal of the URL itself, an expired list, a bad
    configuration and every error about the content (a trust or accreditation error)."""
    for matches, kind in _FAILOVER:
        if matches(exc):
            return kind
    return None


def _is_terminal(exc: BaseException) -> bool:
    """Errors that must reach the caller at once, on any node: an expired list is expired on
    every node, a bad configuration is the caller's, and a URL the guard or the session's pin
    refuses is an attack or a bug, never a flaky node."""
    return isinstance(exc, (NodeListExpired, NodeClientConfigError)) or (
        isinstance(exc, HttpForbiddenHost) and not isinstance(exc, HttpForbiddenAddress))


def _failure_of(origin: str, exc: BaseException) -> NodeFailure | None:
    kind = classify(exc)
    return None if kind is None else NodeFailure(origin, kind, _status(exc))


# --------------------------------------------------------------------------- #
# A session: one node, no failover
# --------------------------------------------------------------------------- #

class NodeSession:
    """One node, for one attempt of a walk. ``resolver`` is a fresh
    :class:`~openvc_ebsi.versioning.DidEbsiResolver` on ``base=origin`` whose only fetch is
    :meth:`get_json`; nothing is carried over from another session.

    :meth:`get_json` refuses (:class:`~openvc_ebsi.http.HttpForbiddenHost`, before any socket) a
    URL whose origin is not this node's, compared as the TIR adapters' own pin does (an absent
    https port is 443, so ``:443`` passes and ``:8443`` does not). The client's allow-list
    covers every node of the environment; this check is what stops a body served by node A from
    steering a read to node B, whatever an adapter does.

    The session records the first node failure it sees (:attr:`failure`) and the first terminal
    error. :meth:`EbsiNodeClient.run` discards an attempt that recorded either, even when the
    walk caught the exception and returned a value."""

    def __init__(self, http: EbsiHttpClient, origin: str, decode_jwt: DecodeJwt,
                 didr: str, tir: str) -> None:
        self._http = http
        self.origin = origin
        self._pin = _origin(origin)
        self._failure: NodeFailure | None = None
        self._terminal: BaseException | None = None
        self.resolver = DidEbsiResolver(
            self.get_json, decode_jwt, base=origin,
            didr=did_registry_adapter(didr), tir=tir_adapter(tir))

    @property
    def failure(self) -> NodeFailure | None:
        """The first node failure this session saw, or ``None``."""
        return self._failure

    def get_json(self, url: str) -> dict[str, Any]:
        try:
            self._http._check_valid()               # expired is expired on every node
            if not isinstance(url, str):
                raise HttpForbiddenHost(f"URL must be a str, not {type(url).__name__}")
            text = str.__str__(url)         # the text checked is the text fetched (#266)
            if not _on_origin(text, self._pin):
                raise HttpForbiddenHost(
                    f"URL is not on this session's node: {url_repr(text)}", url=text)
            return self._http.get_json(text)
        except EbsiError as exc:
            self._note(exc)
            raise

    def _note(self, exc: BaseException) -> None:
        if _is_terminal(exc):
            if self._terminal is None:
                self._terminal = exc
            return
        if self._failure is None:
            self._failure = _failure_of(self.origin, exc)


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Verdict:
    """A memoised health verdict: ``failure`` is ``None`` for a healthy node."""

    failure: NodeFailure | None


def _alive(body: bytes) -> bool:
    """Whether a ``/v1/alive`` body says the node is healthy: a JSON object whose
    ``health_global`` is the ``int`` 1. ``true``, ``1.0``, ``"1"`` and everything else are not
    (``True == 1`` and ``1.0 == 1`` in Python, so the type is checked, not the value alone)."""
    try:
        data = _json.loads(body)
    except (ValueError, RecursionError):
        return False
    if type(data) is not dict:
        return False
    value = data.get("health_global")
    return type(value) is int and value == 1


class EbsiNodeClient:
    """A client for ONE environment's verified nodes. Build it with :func:`for_nodes`.

    ``environment`` is the verifier's label (``pilot`` / ``preprod`` / ``prod``), ``expires``
    the list's, ``origins`` the nodes in list order and ``http`` the one pooled
    :class:`~openvc_ebsi.http.EbsiHttpClient` (allow-list: exactly the nodes' hosts; bound to
    ``expires`` by the injected clock) every session shares. A context manager: leaving it
    closes the pool.

    **Rebuild before ``expires``.** At or after it every read (:meth:`run`, :meth:`session`,
    :meth:`check_health` and a session's ``get_json``) raises
    :class:`~openvc_ebsi.errors.NodeListExpired` and no request is sent; there is no grace and no
    refresh. ``close`` and the context-manager methods only release the pool, and work at any
    time."""

    def __init__(
        self, *, environment: str, expires: datetime, origins: tuple[str, ...],
        http: EbsiHttpClient, policy: NodePolicy, max_nodes: int, health: TtlCache,
        decode_jwt: DecodeJwt, didr: str, tir: str,
    ) -> None:
        self.environment = environment
        self.expires = expires
        self.origins = origins
        self.http = http
        self._origin_set = frozenset(origins)
        self._policy = policy
        self._max_nodes = max_nodes
        self._health = health
        self._decode_jwt = decode_jwt
        self._didr = didr
        self._tir = tir

    # -- health -------------------------------------------------------------- #

    def check_health(self, origin: str) -> bool:
        """``GET {origin}/v1/alive``: **one attempt**, never retried, never read from or
        written to the response cache. Healthy only on a 200 whose body is a JSON object with
        ``health_global`` the ``int`` 1; everything else (another status, a body that is not
        that, a redirect, a firewall page, a timeout, a body past the cap) is unhealthy, fail
        closed. Always sends a fresh probe and records the verdict, which :meth:`run` then
        reuses for ``health_ttl_s``. With an address guard (the default) the one attempt reaches
        the node's FIRST validated address only (see :func:`for_nodes`). Raises
        :class:`NodeListExpired` (never ``False``) once the list has expired, and
        :class:`NodeClientConfigError` for an *origin* that is not one of :attr:`origins`."""
        origin = self._member(origin)
        failure = self._probe(origin)
        self._health.set(origin, _Verdict(failure))
        return failure is None

    def _probe(self, origin: str) -> NodeFailure | None:
        try:
            reply = self.http.probe(f"{origin}{ALIVE_PATH}")
        except (NodeListExpired, NodeClientConfigError):
            raise
        except EbsiError as exc:
            return NodeFailure(origin, "unhealthy", _status(exc))
        if reply.status == 200 and _alive(reply.body):
            return None
        return NodeFailure(origin, "unhealthy", reply.status)

    # -- sessions and walks -------------------------------------------------- #

    def session(self, origin: str) -> NodeSession:
        """A session on *origin*: one node, no failover. Raises :class:`NodeListExpired` once
        the list has expired and :class:`NodeClientConfigError` for an origin that is not one
        of :attr:`origins`."""
        origin = self._member(origin)
        self.http._check_valid()
        return NodeSession(self.http, origin, self._decode_jwt, self._didr, self._tir)

    def run(self, walk: Callable[[NodeSession], T]) -> T:
        """Run *walk* on one node from start to end; when that node fails, run it again from the
        start on the next candidate. Returns what the first successful run returned.

        Candidates come from the policy, in its order, each at most once per call; one known
        unhealthy within ``health_ttl_s`` is skipped without a request; at most ``max_nodes``
        cost a request (a probe or a walk). A candidate with no fresh verdict is probed first
        (lazily, one at a time, never all of them: EBSI's documented limit is 20 requests per
        second per client IP). A node failure (see the module docstring) moves on and marks the
        node unhealthy for ``health_ttl_s``. Everything else propagates at once: an expired
        list (:class:`NodeListExpired`, never :class:`NoHealthyNode`, and no second node is
        tried), :class:`NodeClientConfigError`, a refusal of an off-node URL, and every error
        that is about the content or is a node's *answer* (a 404 included).

        **A walk must be re-runnable**: it is run again, from its first read, on the next node.
        The library's walks are (EBSI is read-only); a *walk* with effects of its own (its own
        ``resolve_status_list`` fetches, say) has them again. An attempt during which the
        session saw a node failure is discarded even if the walk caught the exception and
        returned a value.

        Raises :class:`NoHealthyNode` when no candidate could run the walk."""
        self.http._check_valid()
        failures: list[NodeFailure] = []
        spent = 0
        for origin in self._order():
            verdict = self._health.get(origin)
            if verdict is not None and verdict.failure is not None:
                failures.append(verdict.failure)       # known bad, inside its TTL: free
                continue
            if spent >= self._max_nodes:
                break
            spent += 1
            if verdict is None:
                probed = self._probe(origin)
                self._health.set(origin, _Verdict(probed))
                if probed is not None:
                    self._failed(probed, failures)
                    continue
            session = NodeSession(self.http, origin, self._decode_jwt, self._didr, self._tir)
            try:
                value = walk(session)
            except EbsiError as exc:
                if session._terminal is not None:
                    raise session._terminal
                if _is_terminal(exc):
                    raise
                # Only a failure the SESSION saw is this node's: the walk's own fetches
                # (a status-list lookup through some other client, say) are not blamed on it.
                failure = session.failure
                if failure is None:
                    raise
            else:
                if session._terminal is not None:        # a swallowed expiry or refusal
                    raise session._terminal
                failure = session.failure
                if failure is None:
                    return value
            self._health.set(origin, _Verdict(failure))
            self._failed(failure, failures)
        raise NoHealthyNode(tuple(failures))

    # -- internals ----------------------------------------------------------- #

    def _failed(self, failure: NodeFailure, failures: list[NodeFailure]) -> None:
        failures.append(failure)
        # origin (a validated bare origin), kind (a closed set) and status: never a body, a
        # header value, a Location or an exception message
        logger.warning("ebsi node failover: origin=%s kind=%s status=%s",
                       failure.origin, failure.kind, failure.status)

    def _member(self, origin: object) -> str:
        if type(origin) is not str or origin not in self._origin_set:
            raise NodeClientConfigError(
                f"not a node of this client's {self.environment} list: {url_repr(origin)}")
        return origin

    def _order(self) -> list[str]:
        """The policy's order, checked: untrusted output, so every item must be a member of
        :attr:`origins` (the exact string), at most once, and there must be one. Bounded: a
        policy that never stops is cut after one item more than there are nodes."""
        limit = len(self.origins)
        try:
            items = list(islice(iter(self._policy(self.origins)), limit + 1))
        except Exception as exc:                  # the policy is the caller's code
            raise NodeClientConfigError(
                f"the node policy failed: {type(exc).__name__}") from exc
        if not items:
            raise NodeClientConfigError("the node policy named no node")
        seen: set[str] = set()
        for item in items:
            if type(item) is not str or item not in self._origin_set:
                raise NodeClientConfigError(
                    f"the node policy named a node that is not in the list: {url_repr(item)}")
            if item in seen:
                raise NodeClientConfigError(
                    f"the node policy named a node twice: {url_repr(item)}")
            seen.add(item)
        return items

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> "EbsiNodeClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #

def _checked_result(result: object) -> tuple[str, datetime, tuple[str, ...]]:
    """``(environment, expires, origins)`` of a verifier result, or
    :class:`NodeClientConfigError`. A result can be built by hand, so the type alone is not
    trusted: the nodes are re-validated with the verifier's own origin rule
    (:func:`~openvc_ebsi.nodes.check_node_origin`, which also refuses an environment that is
    not ``pilot``, ``preprod`` or ``prod``), each field is read once, and nothing is returned
    unless every node is a bare ASCII origin of the result's environment, once."""
    if not isinstance(result, VerifiedNodeList):
        raise NodeClientConfigError(
            f"result must be the VerifiedNodeList that verify_node_list returns, not "
            f"{type(result).__name__}")
    environment, nodes, expires = result.environment, result.nodes, result.expires   # read once
    instant = _as_utc(expires, "the result's expires")     # None and non-datetimes are refused
    if type(nodes) is not tuple or not 1 <= len(nodes) <= MAX_NODES:
        raise NodeClientConfigError(
            f"the result's nodes must be a tuple of 1 to {MAX_NODES} nodes")
    origins: list[str] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, Node):
            raise NodeClientConfigError(f"the result's nodes[{index}] is not a Node")
        origin, host = node.origin, node.host                          # read once
        try:
            check_node_origin(origin, environment, f"nodes[{index}].origin")
        except NodeListError as exc:
            raise NodeClientConfigError(str(exc)) from exc
        if host != origin[len("https://"):]:
            raise NodeClientConfigError(
                f"nodes[{index}].host is not the host of its origin: {url_repr(host)}")
        if origin in origins:
            raise NodeClientConfigError(f"nodes[{index}].origin is listed twice: "
                                        f"{url_repr(origin)}")
        origins.append(origin)
    return environment, instant, tuple(origins)


def _checked_int(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise NodeClientConfigError(
            f"{name} must be an int from {low} to {high}, not {safe_repr(value)}")
    return value


#: The longest span (seconds) any duration argument takes: about 31 years. It only keeps every
#: later conversion to ``float`` and every socket timeout in range (``10**400`` is an ``int`` that
#: ``float()`` and ``math.isfinite`` both refuse with an ``OverflowError``).
_MAX_SECONDS = 10**9

#: The widest reading the health memo's monotonic clock may give, either way.
_MAX_MONOTONIC = 2**63


def _checked_seconds(value: object, name: str, *, zero_ok: bool = False) -> float:
    """*value* as a float number of seconds: a real ``int`` or ``float`` (not a ``bool``),
    above 0 (from 0 when *zero_ok*) and at most :data:`_MAX_SECONDS`, else
    :class:`NodeClientConfigError`. Compared before it is converted, so an ``int`` too large for
    a float, ``nan`` and ``inf`` are refused and never raise anything else."""
    if type(value) in (int, float):
        number = cast(float, value)
        if (0 <= number if zero_ok else 0 < number) and number <= _MAX_SECONDS:
            return float(number)
    raise NodeClientConfigError(
        f"{name} must be a number of seconds {'from 0' if zero_ok else 'above 0'} and at most "
        f"{_MAX_SECONDS}, not {safe_repr(value)}")


def _checked_retry(retry: object) -> RetryPolicy:
    """*retry* when it is a :class:`RetryPolicy` a request loop can run: at least one attempt and
    backoff bounds that ``time.sleep`` accepts. ``attempts=0`` would otherwise be reported as
    an outage (no request is ever made), and a negative or ``nan`` backoff would raise a bare
    ``ValueError`` from ``time.sleep`` in the middle of a walk."""
    if not isinstance(retry, RetryPolicy):
        raise NodeClientConfigError(
            f"retry must be a RetryPolicy or None, not {type(retry).__name__}")
    attempts, statuses = retry.attempts, retry.retry_statuses                   # read once
    if type(attempts) is not int or attempts < 1:
        raise NodeClientConfigError(
            f"retry.attempts must be an int of at least 1, not {safe_repr(attempts)}")
    if type(statuses) not in (set, frozenset) or any(type(s) is not int for s in statuses):
        raise NodeClientConfigError("retry.retry_statuses must be a set of int statuses")
    _checked_seconds(retry.backoff_base_s, "retry.backoff_base_s", zero_ok=True)
    _checked_seconds(retry.backoff_max_s, "retry.backoff_max_s", zero_ok=True)
    return retry


def _checked_monotonic(clock: Callable[[], float]) -> Callable[[], float]:
    """The health memo's monotonic clock, read through a check at EVERY reading (the wall clock's
    own rule, :func:`~openvc_ebsi.http.read_clock`): a clock that raises (an object that is not
    callable included), or returns anything but a finite ``int`` or ``float``, is
    :class:`NodeClientConfigError` and never a bare ``TypeError`` out of the cache. A reading
    must be inside ``+-2**63``, so the cache's own arithmetic cannot overflow."""
    def read() -> float:
        try:
            reading = clock()
        except Exception as exc:             # a caller's clock may raise anything
            raise NodeClientConfigError(
                f"health_clock raised {type(exc).__name__}") from exc
        if type(reading) not in (int, float) or not -_MAX_MONOTONIC < reading < _MAX_MONOTONIC:
            raise NodeClientConfigError(
                f"health_clock must return a finite number, not {safe_repr(reading)}")
        return float(reading)
    return read


def _checked_user_agent(value: object) -> str:
    """A ``User-Agent`` value: a ``str`` of visible ASCII and spaces, 1 to 256 characters.

    Measured with httpx on a loopback connection: a CR, LF or NUL is a ``LocalProtocolError`` (a
    ``TransportError``) on every request, which a walk reads as an outage; a non-ASCII value is a
    bare ``UnicodeEncodeError`` and a non-``str`` a bare ``TypeError`` out of the ``httpx.Client``
    constructor. The length bound, and the refusal of an empty value, are this function's own:
    httpx sends both."""
    if (type(value) is not str or not 1 <= len(value) <= 256
            or not all(" " <= ch <= "~" for ch in value)):
        raise NodeClientConfigError(
            f"user_agent must be 1 to 256 characters of visible ASCII, not {safe_repr(value)}")
    return value


def for_nodes(
    result: VerifiedNodeList,
    *,
    clock: Callable[[], datetime],
    decode_jwt: DecodeJwt,
    policy: NodePolicy = random_order,
    max_nodes: int = 3,
    health_ttl_s: float = 60.0,
    didr: str = "core-v1",
    tir: str = "core-v1",
    timeout_s: float = 10.0,
    cache: TtlCache | None = None,
    cache_ttl_s: float = 300.0,
    retry: RetryPolicy | None = None,
    user_agent: str = f"openvc-core/{__version__}",
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    address_guard: AddressGuard | None = _DEFAULT_ADDRESS_GUARD,
    health_clock: Callable[[], float] = time.monotonic,
) -> EbsiNodeClient:
    """Build an :class:`EbsiNodeClient` from the result of
    :func:`~openvc_ebsi.nodes.verify_node_list`.

    * *result*: the verifier's frozen result, for ONE environment. It is re-validated (a result
      can be built by hand): a non-empty tuple of bare ASCII ``https://host`` origins of its
      environment, none twice, else :class:`NodeClientConfigError`. The allow-list is exactly
      its hosts; the client then admits ``https`` at port 443 of those hosts only (#318).
      There is no ``extra_hosts``, no ``allowed_hosts`` (a ``TypeError``), no way to merge two
      results, and ``verify_tls`` is not exposed: a node is authenticated by its name's
      certificate and nothing else.
    * *clock*: the wall clock that decides the list's validity, a callable returning a
      ``datetime`` (a naive one is UTC). A result already expired at its reading is
      :class:`NodeListExpired`; a clock that raises or returns anything but a ``datetime`` is
      :class:`NodeClientConfigError`, now and at every later read. It is read before every
      request attempt, not just now.
    * *decode_jwt*: how the TIR adapters read an accreditation token, for example
      ``VcJwtProofSuite().peek_claims``.
    * *policy*: orders the candidates (default :func:`random_order`); its output is checked.
    * *max_nodes* (default 3): at most this many candidates cost a request per ``run``.
      *health_ttl_s* (default 60): how long a health verdict, or a node's failed read, is
      remembered. Both are proposals, not facts about EBSI.
    * *didr*, *tir*: adapter names (``"core-v1"``); the legacy lane stays :func:`for_ebsi`.
    * *retry* defaults to :data:`NODE_RETRY` (two attempts), not the three of ``for_ebsi``:
      with another node to try, a second retry buys little and costs a dead node its timeout.
    * *address_guard*: **on by default** (``AddressGuard()``): the allow-list matches host
      NAMES, and these names are node operators' own domains, so every request resolves the name,
      refuses a node with any non-public address and connects to the validated one
      (:class:`~openvc_ebsi.http.AddressGuard`). Pass ``address_guard=None`` to opt out. The
      guard cannot work behind an environment proxy (``HTTPS_PROXY`` / ``ALL_PROXY``, or the
      system proxy on macOS and Windows): ``for_nodes`` then raises
      :class:`~openvc_ebsi.http.HttpAddressGuardUnavailable` instead of silently dropping the
      control. Unset the proxy, or pass ``address_guard=None`` to go through it. **The health
      probe reaches only a node's FIRST validated address**: the guard hands out one address per
      attempt, in the resolver's order, and a probe is one attempt, while a read retries on to the
      next address. A node whose first address this host cannot reach (an AAAA record first, on a
      host with no IPv6 route) is therefore reported unhealthy, and remembered so for
      *health_ttl_s*, although its reads would succeed. Fix it where it happens: have the
      resolver answer an address this host can reach first (``AddressGuard(resolver=...)``).
    * *timeout_s*, *cache_ttl_s*, *max_response_bytes*, *user_agent*, *cache*: passed to
      :class:`~openvc_ebsi.http.EbsiHttpClient`. *health_clock*: the monotonic clock of the
      health memo (a test seam); a reading that is not a finite number is
      :class:`NodeClientConfigError`, now and at every later read.

    Every argument is checked before an ``httpx.Client`` is built, and one that is out of range
    (a duration that is not above 0, a *retry* with no attempt or a negative backoff, a
    *max_response_bytes* below 1, a *user_agent* that is not 1 to 256 characters of visible
    ASCII, a *cache* without
    ``get`` and ``set``, an *address_guard* that is not an :class:`~openvc_ebsi.http.AddressGuard`,
    a *health_clock* that is not a clock) is :class:`NodeClientConfigError`: never an outage
    reported by :class:`NoHealthyNode`, and never a bare exception from the middle of a walk.
    Durations are at most 10**9 seconds."""
    if not callable(clock):
        raise NodeClientConfigError(f"clock must be a callable, not {type(clock).__name__}")
    if not callable(decode_jwt):
        raise NodeClientConfigError(
            f"decode_jwt must be a callable, not {type(decode_jwt).__name__}")
    if not callable(policy):
        raise NodeClientConfigError(f"policy must be a callable, not {type(policy).__name__}")
    _checked_int(max_nodes, "max_nodes", 1, MAX_NODES)
    health_ttl = _checked_seconds(health_ttl_s, "health_ttl_s")
    timeout = _checked_seconds(timeout_s, "timeout_s")
    cache_ttl = _checked_seconds(cache_ttl_s, "cache_ttl_s")
    if type(max_response_bytes) is not int or max_response_bytes < 1:
        raise NodeClientConfigError(
            f"max_response_bytes must be an int of at least 1, not {safe_repr(max_response_bytes)}")
    policy_retry = NODE_RETRY if retry is None else _checked_retry(retry)
    _checked_user_agent(user_agent)
    if cache is not None and not (
            callable(getattr(cache, "get", None)) and callable(getattr(cache, "set", None))):
        raise NodeClientConfigError(
            f"cache must be None or have callable get and set, not {type(cache).__name__}")
    if address_guard is not None and not isinstance(address_guard, AddressGuard):
        raise NodeClientConfigError(
            f"address_guard must be an AddressGuard or None, not {type(address_guard).__name__}")
    monotonic = _checked_monotonic(health_clock)
    monotonic()                         # a clock that is not one (not callable included) fails now
    environment, expires, origins = _checked_result(result)
    try:                                        # the adapter names are checked once, up front
        did_registry_adapter(didr)
        tir_adapter(tir)
    except (ValueError, TypeError) as exc:
        raise NodeClientConfigError(f"unknown adapter name: {bounded_text(exc)}") from exc
    if read_clock(clock) >= expires:
        raise NodeListExpired(
            f"the {environment} node list expired at {expires.isoformat()}: verify a newer one")

    http = EbsiHttpClient(
        allowed_hosts={origin[len("https://"):] for origin in origins},
        timeout_s=timeout, cache=cache, cache_ttl_s=cache_ttl,
        retry=policy_retry, user_agent=user_agent,
        max_response_bytes=max_response_bytes, address_guard=address_guard,
        valid_until=expires, clock=clock)
    return EbsiNodeClient(
        environment=environment, expires=expires, origins=origins, http=http, policy=policy,
        max_nodes=max_nodes,
        health=TtlCache(ttl_s=health_ttl, max_entries=MAX_NODES, clock=monotonic),
        decode_jwt=decode_jwt, didr=didr, tir=tir)
