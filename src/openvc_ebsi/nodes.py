"""openvc_ebsi.nodes — verify the EBSI Trusted Nodes List (TNL), offline.

EBSI no longer publishes a host to call: a client picks a *node* from a JSON list signed
with OpenPGP (``https://tnl.ebsi.eu``, source ``gitlab.com/europeum/public/trusted-nodes-list``).
:func:`verify_node_list` takes the four byte strings EBSI serves and either returns the
nodes of ONE environment as validated origins or raises a typed
:class:`~openvc_ebsi.errors.NodeListError`. It is a pure function: it reads no clock
(``now`` is a required argument), opens no socket, and keeps nothing (ADR-0007, ADR-0009).

The chain it checks::

    anchor (Europeum key-list key; pinned in the wheel, overridable)
       | signs trusted-keys.json.sig        over  trusted-keys.json   (custodians, threshold)
       v
    custodians   (at least ``threshold`` distinct primary keys must sign)
       | sign tnl.json.sig                  over  tnl.json            (nodes per environment)
       v
    VerifiedNodeList

**Authenticated before parsed.** The only bytes read before a signature is checked are the
two detached-signature files (4 KiB cap each). ``trusted-keys.json`` is parsed after the
anchor's signature verifies; the custodian key blocks inside it after that; ``tnl.json``
only once the threshold of custodians has signed it.

**What it gives, and what it does not.** The list authenticates the *operator* of each
node, not the content a node serves (ADR-0009 D7), and the chain's real root is the single
anchor key. **Persistence is the caller's**: :class:`Accepted` pairs for the list and the
key list are required arguments, but ``None`` ("first run") is always passable, so what
bounds a caller that persists nothing is the two shipped floors (:data:`LIST_VERSION_FLOOR`,
:data:`KEYS_VERSION_FLOOR`, raised at each release), the optional ``max_age`` and
``min_threshold``. After you decide to accept a result, store its ``accepted_list`` and
``accepted_keys`` and pass them back next time.

It imports nothing that needs the ``ebsi`` extra (no ``httpx``).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from openvc import _json
from openvc.proof._verify_common import safe_repr, utc_instant
from openvc_ebsi import _openpgp
from openvc_ebsi.errors import (
    NodeListConfigError,
    NodeListEnvironmentMissing,
    NodeListExpired,
    NodeListMalformed,
    NodeListNotYetValid,
    NodeListRollback,
    NodeListSignatureError,
    NodeListStale,
    NodeListThresholdError,
    OpenPgpError,
)

__all__ = [
    "Accepted", "Anchor", "DEFAULT_MIN_THRESHOLD", "EUROPEUM_KEY_LIST_ANCHOR",
    "KEYS_VERSION_FLOOR", "LIST_VERSION_FLOOR", "Node", "VerifiedNodeList",
    "verify_node_list",
]

# ---- shipped constants (raised at each release; see the wiki) -----------------------------
#: The lowest ``tnl.json`` ``version`` accepted. A floor can only reject, so it must never
#: exceed a version EBSI has published: 4 is the newest on 2026-10-16.
LIST_VERSION_FLOOR = 4
#: The lowest ``trusted-keys.json`` ``version`` accepted (1 is the only one that exists).
KEYS_VERSION_FLOOR = 1
#: ``min_threshold`` when the caller passes none: the live value, so a key list that lowers
#: the threshold to 1 fails closed until the caller says that is intended.
DEFAULT_MIN_THRESHOLD = 2

# ---- bounds ------------------------------------------------------------------------------
MAX_LIST_BYTES = 262144     # tnl.json; the live file is 7068 bytes
MAX_KEYS_BYTES = 65536      # trusted-keys.json; the live file is 1811 bytes
MAX_CUSTODIANS = 16         # the live list has 2
MAX_NODES = 512             # nodes in the whole list; the live list has 45
MAX_VERSION = 2 ** 63 - 1   # a version above this is refused as malformed
_SKEW = timedelta(seconds=300)          # the publisher's 5 minutes of clock skew
_MAX_VALIDITY = timedelta(days=90)      # expires is at most 90 days after issued

_ENVIRONMENTS = ("pilot", "preprod", "prod")
_PREFIX = {
    "pilot": "https://api-pilot.ebsi.",
    "preprod": "https://api-preprod.ebsi.",
    "prod": "https://api.ebsi.",
}
# fullmatch with explicit ASCII classes: Python's ``$`` accepts a trailing newline and
# ``\d`` matches other scripts' digits
_URL = re.compile(r"https://[a-z0-9.-]+")
_COUNTRY = re.compile(r"[A-Z]{2}")
_INSTANT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
_FINGERPRINT = re.compile(r"[0-9A-F]{40}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
# ECMAScript ``\s`` and the characters ``.`` refuses, measured with node 26 over every code
# point: the publisher's schema pattern for ``organisation`` is ``^\S(.*\S)?$``
_ECMA_SPACE = frozenset(
    "\t\n\v\f\r \N{NO-BREAK SPACE}\N{OGHAM SPACE MARK}"
    "\N{EN QUAD}\N{EM QUAD}\N{EN SPACE}\N{EM SPACE}\N{THREE-PER-EM SPACE}"
    "\N{FOUR-PER-EM SPACE}\N{SIX-PER-EM SPACE}\N{FIGURE SPACE}\N{PUNCTUATION SPACE}"
    "\N{THIN SPACE}\N{HAIR SPACE}\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"
    "\N{NARROW NO-BREAK SPACE}\N{MEDIUM MATHEMATICAL SPACE}\N{IDEOGRAPHIC SPACE}"
    "\N{ZERO WIDTH NO-BREAK SPACE}")
_ECMA_LINE_TERMINATORS = frozenset("\n\r\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}")


# ---- the caller-facing types ---------------------------------------------------------------
@dataclass(frozen=True)
class Accepted:
    """What the caller persisted when it last accepted a document: its ``version`` and the
    SHA-256 (64 lower-case hex characters) of the exact bytes. The publisher's rule is
    "higher version, or the same version only if the bytes are identical", which needs both."""
    version: int
    sha256: str

    def __post_init__(self) -> None:
        _accepted_pair(self, "Accepted")


@dataclass(frozen=True)
class Anchor:
    """The key everything is verified from: a primary key's v4 ``fingerprint`` (40
    upper-case hex characters), its ``curve`` (``"P-256"``) and its ``public_point`` (65
    bytes, SEC1 uncompressed). Build one from a key block you obtained out of band with
    :meth:`from_public_key_block`, which recomputes the fingerprint; never download it at
    runtime."""
    fingerprint: str
    curve: str
    public_point: bytes

    def __post_init__(self) -> None:
        _anchor_key(self)

    @classmethod
    def from_public_key_block(cls, block: str | bytes) -> Anchor:
        """The anchor in an ASCII-armored OpenPGP public key block (a ``keylist-key.asc``
        you pinned). The fingerprint is recomputed from the key material."""
        try:
            text = block.decode("ascii") if isinstance(block, (bytes, bytearray)) else block
            key = _openpgp.read_public_key_block(text)
        except (UnicodeDecodeError, OpenPgpError) as exc:
            raise NodeListConfigError(f"the anchor key block cannot be read: {exc}") from exc
        return cls(key.fingerprint, key.curve, key.point)


@dataclass(frozen=True)
class Node:
    """One approved node: its bare ``origin`` (``https://host``), the lower-case ``host``,
    and the operator's ISO 3166-1 alpha-2 ``country`` and ``organisation``."""
    origin: str
    host: str
    country: str
    organisation: str


@dataclass(frozen=True)
class VerifiedNodeList:
    """A verified list, bound to the ONE requested ``environment``.

    ``version``, ``issued`` and ``expires`` (aware UTC) are the list's; ``keys_version`` is
    the ``keysVersion`` it names; ``nodes`` are in list order. ``accepted_list`` and
    ``accepted_keys`` are the pairs to persist once the caller decides to accept this
    result (``accepted_keys.version`` is the key list's own version)."""
    environment: str
    version: int
    keys_version: int
    issued: datetime
    expires: datetime
    nodes: tuple[Node, ...]
    accepted_list: Accepted
    accepted_keys: Accepted

    @property
    def hosts(self) -> frozenset[str]:
        """The lower-case hosts, the form ``EbsiHttpClient(allowed_hosts=...)`` takes."""
        return frozenset(node.host for node in self.nodes)


# ---- argument checks ---------------------------------------------------------------------
def _accepted_pair(value: Any, name: str) -> tuple[int, str]:
    version, digest = value.version, value.sha256            # read once
    if type(version) is not int or not 1 <= version <= MAX_VERSION:
        raise NodeListConfigError(
            f"{name}.version must be an int of at least 1, not {safe_repr(version)}")
    if type(digest) is not str or _SHA256_HEX.fullmatch(digest) is None:
        raise NodeListConfigError(
            f"{name}.sha256 must be 64 lower-case hex characters, not {safe_repr(digest)}")
    return version, digest


def _accepted(value: Any, name: str) -> tuple[int, str] | None:
    if value is None:
        return None
    if not isinstance(value, Accepted):
        raise NodeListConfigError(
            f"{name} must be an Accepted pair or None, not {safe_repr(value)}")
    return _accepted_pair(value, name)


def _anchor_key(anchor: Any) -> _openpgp.PublicKey:
    if not isinstance(anchor, Anchor):
        raise NodeListConfigError(f"anchor must be an Anchor, not {safe_repr(anchor)}")
    fingerprint, curve, point = anchor.fingerprint, anchor.curve, anchor.public_point
    if type(fingerprint) is not str or _FINGERPRINT.fullmatch(fingerprint) is None:
        raise NodeListConfigError("anchor.fingerprint must be 40 upper-case hex characters")
    try:
        return _openpgp.make_public_key(curve, point, fingerprint)
    except OpenPgpError as exc:
        raise NodeListConfigError(f"anchor is malformed: {exc}") from exc


def _floor(value: Any, name: str) -> int:
    if type(value) is not int or value < 1:
        raise NodeListConfigError(f"{name} must be an int of at least 1, not {safe_repr(value)}")
    return value


def _snapshot(value: Any, name: str, cap: int) -> bytes:
    """The bytes of *value*, copied once through the buffer protocol: a ``bytes`` subclass
    or a ``bytearray`` that answers differently on each read cannot split what is verified
    from what is parsed and hashed."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise NodeListConfigError(f"{name} must be the bytes as served, not {safe_repr(value)}")
    try:
        with memoryview(value) as view:
            if view.ndim != 1 or view.itemsize != 1:
                raise NodeListConfigError(f"{name} must be a flat byte buffer")
            if view.nbytes > cap:
                raise NodeListMalformed(f"{name} is {view.nbytes} bytes, over the {cap} cap")
            return view.tobytes()
    except (TypeError, ValueError) as exc:
        raise NodeListConfigError(f"{name} cannot be read as bytes") from exc


# ---- document checks ---------------------------------------------------------------------
def _load_object(raw: bytes, name: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NodeListMalformed(f"{name} is not UTF-8") from exc
    if text.startswith("\N{ZERO WIDTH NO-BREAK SPACE}"):
        raise NodeListMalformed(f"{name} starts with a byte order mark")
    try:
        value = _json.loads(text, reject_ambiguous=True)
    except ValueError as exc:
        raise NodeListMalformed(f"{name} is not acceptable JSON: {exc}") from exc
    if type(value) is not dict:
        raise NodeListMalformed(f"{name} must be a JSON object")
    return value


def _members(obj: dict[str, Any], names: frozenset[str], what: str) -> None:
    if set(obj) != names:
        raise NodeListMalformed(f"{what} must have exactly the members {sorted(names)}")


def _version(value: Any, what: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_VERSION:
        raise NodeListMalformed(f"{what} must be an integer of at least 1, not {safe_repr(value)}")
    return value


def _instant(value: Any, what: str) -> datetime:
    match = _INSTANT.fullmatch(value) if type(value) is str else None
    if match is None:
        raise NodeListMalformed(
            f"{what} is not a YYYY-MM-DDTHH:MM:SSZ timestamp: {safe_repr(value)}")
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as exc:
        raise NodeListMalformed(f"{what} is not a real date and time: {safe_repr(value)}") from exc


def _check_pair(what: str, version: int, digest: str, floor: int,
                last: tuple[int, str] | None) -> None:
    """The publisher's rollback rule: below the floor or lower than the last accepted
    version is a rollback; equal is fine only for the same bytes."""
    if version < floor:
        raise NodeListRollback(f"{what} version {version} is below the shipped floor {floor}")
    if last is not None:
        if version < last[0]:
            raise NodeListRollback(
                f"{what} version {version} is lower than the last accepted {last[0]}")
        if version == last[0] and digest != last[1]:
            raise NodeListRollback(f"{what} version {version} is the last accepted version "
                                   "with different bytes")


def _check_host(host: str, what: str) -> None:
    labels = host.split(".")
    if len(host) > 253 or any(not 1 <= len(label) <= 63 or label[0] == "-" or label[-1] == "-"
                              for label in labels):
        raise NodeListMalformed(f"{what}: {safe_repr(host)} is not a DNS name")


def _node(entry: Any, environment: str, seen: set[str], what: str) -> Node:
    if type(entry) is not dict:
        raise NodeListMalformed(f"{what} must be a JSON object")
    _members(entry, frozenset({"url", "country", "organisation"}), what)
    url, country, organisation = entry["url"], entry["country"], entry["organisation"]
    if type(url) is not str or _URL.fullmatch(url) is None:
        raise NodeListMalformed(f"{what}.url is not a bare https origin: {safe_repr(url)}")
    if not url.startswith(_PREFIX[environment]):
        raise NodeListMalformed(f"{what}.url does not start with {_PREFIX[environment]}")
    host = url[len("https://"):]
    _check_host(host, f"{what}.url")
    if url in seen:
        raise NodeListMalformed(f"{what}.url is listed twice: {safe_repr(url)}")
    seen.add(url)
    if type(country) is not str or _COUNTRY.fullmatch(country) is None:
        raise NodeListMalformed(f"{what}.country is not two upper-case letters")
    if type(organisation) is not str:
        raise NodeListMalformed(f"{what}.organisation must be a string")
    _json.utf8(organisation, error=NodeListMalformed, what=f"{what}.organisation")
    if (not 1 <= len(organisation) <= 200 or organisation[0] in _ECMA_SPACE
            or organisation[-1] in _ECMA_SPACE
            or not _ECMA_LINE_TERMINATORS.isdisjoint(organisation)):
        raise NodeListMalformed(f"{what}.organisation is empty, over 200 characters, has leading "
                                "or trailing whitespace or contains a line terminator")
    return Node(url, host, country, organisation)


@dataclass(frozen=True)
class _Document:
    version: int
    keys_version: int
    issued: datetime
    expires: datetime
    environments: dict[str, tuple[Node, ...]]


def _parse_list(raw: bytes) -> _Document:
    doc = _load_object(raw, "tnl.json")
    _members(doc, frozenset({"version", "keysVersion", "issued", "expires", "environments"}),
             "tnl.json")
    version = _version(doc["version"], "tnl.json version")
    keys_version = _version(doc["keysVersion"], "tnl.json keysVersion")
    issued = _instant(doc["issued"], "tnl.json issued")
    expires = _instant(doc["expires"], "tnl.json expires")
    if not issued < expires or expires - issued > _MAX_VALIDITY:
        raise NodeListMalformed("tnl.json expires must be after issued and at most 90 days after")
    envs = doc["environments"]
    if type(envs) is not dict or not 1 <= len(envs) <= len(_ENVIRONMENTS) \
            or not set(envs) <= set(_ENVIRONMENTS):
        raise NodeListMalformed("tnl.json environments must hold one to three of "
                                "pilot, preprod and prod, and nothing else")
    seen: set[str] = set()
    total = 0
    parsed: dict[str, tuple[Node, ...]] = {}
    for env in _ENVIRONMENTS:
        if env not in envs:
            continue
        entries = envs[env]
        if type(entries) is not list or not entries:
            raise NodeListMalformed(f"tnl.json environments.{env} must be a non-empty array")
        total += len(entries)
        if total > MAX_NODES:
            raise NodeListMalformed(f"tnl.json lists more than {MAX_NODES} nodes")
        parsed[env] = tuple(_node(entry, env, seen, f"environments.{env}[{i}]")
                            for i, entry in enumerate(entries))
    return _Document(version, keys_version, issued, expires, parsed)


@dataclass(frozen=True)
class _Custodian:
    fingerprint: str
    armor: Any


def _parse_key_list(raw: bytes) -> tuple[int, int, list[_Custodian]]:
    doc = _load_object(raw, "trusted-keys.json")
    _members(doc, frozenset({"version", "threshold", "keys"}), "trusted-keys.json")
    version = _version(doc["version"], "trusted-keys.json version")
    threshold, keys = doc["threshold"], doc["keys"]
    if type(threshold) is not int:
        raise NodeListMalformed(
            f"trusted-keys.json threshold must be an integer, not {safe_repr(threshold)}")
    if type(keys) is not list or not 1 <= len(keys) <= MAX_CUSTODIANS:
        raise NodeListMalformed(
            f"trusted-keys.json keys must be an array of 1 to {MAX_CUSTODIANS} custodians")
    custodians = []
    for i, entry in enumerate(keys):
        if type(entry) is not dict:
            raise NodeListMalformed(f"trusted-keys.json keys[{i}] must be a JSON object")
        _members(entry, frozenset({"fingerprint", "publicKey"}), f"trusted-keys.json keys[{i}]")
        fingerprint = entry["fingerprint"]
        if type(fingerprint) is not str or _FINGERPRINT.fullmatch(fingerprint) is None:
            raise NodeListMalformed(
                f"trusted-keys.json keys[{i}].fingerprint is not 40 upper-case hex characters")
        custodians.append(_Custodian(fingerprint, entry["publicKey"]))
    return version, threshold, custodians


def _read_custodians(custodians: list[_Custodian]) -> dict[str, _openpgp.PublicKey]:
    allowed: dict[str, _openpgp.PublicKey] = {}
    points: set[bytes] = set()
    for i, custodian in enumerate(custodians):
        key = _openpgp.read_public_key_block(custodian.armor)
        if key.fingerprint != custodian.fingerprint:
            raise NodeListMalformed(
                f"trusted-keys.json keys[{i}]: the listed fingerprint is not the key's")
        # the same key listed twice under two creation times would be two fingerprints and
        # one signer: refuse the point as well as the fingerprint
        if key.fingerprint in allowed or key.point in points:
            raise NodeListMalformed(f"trusted-keys.json keys[{i}] repeats a custodian")
        allowed[key.fingerprint] = key
        points.add(key.point)
    return allowed


#: Europeum's key-list signing key, as pinned from ``keylist-key.asc`` served by
#: ``tnl.ebsi.eu`` on 2026-10-16 (v4, ECDSA P-256, created 2026-09-30). The fingerprint
#: agrees across ``tnl.ebsi.eu``, the TNL repository's README and the hub documentation;
#: all three are Europeum's own channels, so this is consistency, not independent proof.
EUROPEUM_KEY_LIST_ANCHOR = Anchor(
    fingerprint="ACCC82E5FC8902F114929481747CB65CFB7574F9",
    curve="P-256",
    public_point=bytes.fromhex(
        "048f0be3ec98c5f92f5fded6c485bd008d3c775c068da9d78a1fff7a24758dce9d"
        "1c8daa141ab135ccd70eada1e504cc2d4c105e43cca7b844046ef9eae1469b40"),
)


# ---- the verifier ------------------------------------------------------------------------
def verify_node_list(
    *,
    tnl: bytes,
    tnl_sig: bytes,
    keys: bytes,
    keys_sig: bytes,
    environment: str,
    now: datetime,
    last_accepted_list: Accepted | None,
    last_accepted_keys: Accepted | None,
    anchor: Anchor = EUROPEUM_KEY_LIST_ANCHOR,
    list_floor: int = LIST_VERSION_FLOOR,
    keys_floor: int = KEYS_VERSION_FLOOR,
    max_age: timedelta | None = None,
    min_threshold: int | None = DEFAULT_MIN_THRESHOLD,
) -> VerifiedNodeList:
    """Verify the Trusted Nodes List and return the nodes of *environment*.

    *tnl*, *tnl_sig*, *keys*, *keys_sig* are the bytes of ``tnl.json``, ``tnl.json.sig``,
    ``trusted-keys.json`` and ``trusted-keys.json.sig`` exactly as served (a ``str`` is a
    :class:`NodeListConfigError`: do not re-encode). *environment* is ``"pilot"``,
    ``"preprod"`` or ``"prod"``. *now* is required and read once (a naive datetime is UTC).

    *last_accepted_list* and *last_accepted_keys* are what the caller persisted at its last
    accepted verification (``None`` on a first run; the function cannot tell an honest
    ``None`` from a convenient one). *list_floor* and *keys_floor* default to the shipped
    constants. *max_age* (off by default) rejects a list issued longer ago than that.
    *min_threshold* (default :data:`DEFAULT_MIN_THRESHOLD`; ``None`` for no minimum) rejects
    a key list whose ``threshold`` is below it.

    The order of checks is the security argument: every stage reads only bytes the previous
    one authenticated. Raises a :class:`~openvc_ebsi.errors.NodeListError` subclass and
    nothing else.
    """
    # 1. arguments, then the size caps; the bytes are copied once and only the copies are used
    if type(environment) is not str or environment not in _ENVIRONMENTS:
        raise NodeListConfigError(
            f"environment must be one of pilot, preprod, prod, not {safe_repr(environment)}")
    if now is None:                  # utc_instant(None) means the wall clock; this never reads it
        raise NodeListConfigError("now is required: the verifier reads no clock")
    instant = utc_instant(now, error=NodeListConfigError, name="now")
    last_list = _accepted(last_accepted_list, "last_accepted_list")
    last_keys = _accepted(last_accepted_keys, "last_accepted_keys")
    anchor_key = _anchor_key(anchor)
    list_floor = _floor(list_floor, "list_floor")
    keys_floor = _floor(keys_floor, "keys_floor")
    if max_age is not None and (not isinstance(max_age, timedelta) or max_age <= timedelta(0)):
        raise NodeListConfigError(
            f"max_age must be a positive timedelta or None, not {safe_repr(max_age)}")
    minimum = None if min_threshold is None else _floor(min_threshold, "min_threshold")
    tnl_b = _snapshot(tnl, "tnl", MAX_LIST_BYTES)
    tnl_sig_b = _snapshot(tnl_sig, "tnl_sig", _openpgp.MAX_SIGNATURE_FILE_BYTES)
    keys_b = _snapshot(keys, "keys", MAX_KEYS_BYTES)
    keys_sig_b = _snapshot(keys_sig, "keys_sig", _openpgp.MAX_SIGNATURE_FILE_BYTES)

    # 2. the key list must be signed by the anchor; nothing of `keys` is parsed before this
    anchors = {anchor_key.fingerprint: anchor_key}
    signers = _openpgp.verified_signers(_openpgp.read_signatures(keys_sig_b), keys_b, anchors)
    if anchor_key.fingerprint not in signers:
        raise NodeListSignatureError("trusted-keys.json is not signed by the anchor")

    # 3. the key list: shape, rollback (its own version, which the anchor signs), threshold
    keys_version, threshold, listed = _parse_key_list(keys_b)
    keys_digest = hashlib.sha256(keys_b).hexdigest()
    _check_pair("trusted-keys.json", keys_version, keys_digest, keys_floor, last_keys)
    if not 1 <= threshold <= len(listed):
        raise NodeListMalformed(
            f"trusted-keys.json threshold {safe_repr(threshold)} is not between 1 and the "
            f"{len(listed)} custodians")
    if minimum is not None and threshold < minimum:
        raise NodeListThresholdError(
            f"trusted-keys.json threshold {threshold} is below the minimum {minimum}")

    # 4. the custodian keys (authenticated bytes now): fingerprints recomputed, no duplicate
    custodians = _read_custodians(listed)

    # 5. the node list's signatures: identity from the hashed issuer fingerprint only
    custodian_signers = _openpgp.verified_signers(
        _openpgp.read_signatures(tnl_sig_b), tnl_b, custodians)
    if len(custodian_signers) < threshold:
        raise NodeListThresholdError(
            f"tnl.json is signed by {len(custodian_signers)} distinct custodians, "
            f"{threshold} are required")

    # 6. only now the node list itself
    document = _parse_list(tnl_b)
    list_digest = hashlib.sha256(tnl_b).hexdigest()
    _check_pair("tnl.json", document.version, list_digest, list_floor, last_list)
    if document.keys_version > keys_version:
        raise NodeListRollback(
            f"tnl.json needs key list version {document.keys_version}, "
            f"the key list given is version {keys_version}")
    if instant >= document.expires:
        raise NodeListExpired(f"the node list expired at {document.expires.isoformat()}")
    if document.issued - instant > _SKEW:
        raise NodeListNotYetValid(
            f"the node list was issued at {document.issued.isoformat()}, after now plus 300 s")
    if max_age is not None and instant - document.issued > max_age:
        raise NodeListStale(
            f"the node list was issued at {document.issued.isoformat()}, over max_age ago")
    nodes = document.environments.get(environment)
    if nodes is None:
        raise NodeListEnvironmentMissing(f"the node list has no {environment} environment")
    return VerifiedNodeList(
        environment=environment,
        version=document.version,
        keys_version=document.keys_version,
        issued=document.issued,
        expires=document.expires,
        nodes=nodes,
        accepted_list=Accepted(document.version, list_digest),
        accepted_keys=Accepted(keys_version, keys_digest),
    )
