"""openvc_ebsi.errors — the EBSI-plugin error root.

Sits under openvc's library-wide :class:`~openvc.errors.OpenvcError`, so every EBSI
failure is catchable both as :class:`EbsiError` and as ``OpenvcError``.
"""
from __future__ import annotations

from openvc.errors import OpenvcError


class EbsiError(OpenvcError):
    """Base class for every error the EBSI plugin raises."""


class MalformedRegistryResponse(EbsiError):
    """A registry returned a 200 body that is not the JSON object the adapter needs
    (a ``null`` / array / string / number body, e.g. from a flaky or compromised
    registry). Fails closed as a typed :class:`EbsiError` rather than leaking a bare
    ``AttributeError`` past the error family callers catch."""


class UnknownEbsiEnvironment(EbsiError, ValueError):
    """``for_ebsi`` was given an environment name the table does not hold: an unknown or
    wrong-case string, an empty one, or a value that is not a ``str`` at all (``None``, a
    number, an unhashable ``list``).

    It is also a :class:`ValueError`, which is what ``for_ebsi`` raised for an unknown name
    before this class existed, so ``except ValueError`` keeps working. Code that compares the
    exact class (``type(exc) is ValueError``) must compare this one."""


class NodeListError(EbsiError):
    """Base class for every failure of the Trusted Nodes List verifier
    (:func:`openvc_ebsi.nodes.verify_node_list`).

    The leaves are in the order the verifier can raise them. A caller that only wants
    "do not use this list" catches this class; one that wants to alert differently on
    "the list is old" (:class:`NodeListExpired`) and "the list is forged"
    (:class:`NodeListSignatureError`) catches the leaves."""


class NodeListConfigError(NodeListError):
    """The caller passed a bad argument: an environment that is not ``pilot`` /
    ``preprod`` / ``prod``, a missing or non-datetime ``now``, input that is not
    ``bytes``, a malformed ``Accepted`` pair, anchor, floor, ``min_threshold`` or
    ``max_age``. Nothing about the list is judged: fix the call."""


class NodeListMalformed(NodeListError):
    """A byte string is not shaped the way the Trusted Nodes List protocol says: over its
    size cap, not UTF-8 JSON, a schema or origin rule broken, a listed fingerprint that is
    not the key's, a duplicate custodian, a threshold out of range."""


class OpenPgpError(NodeListMalformed):
    """The minimal OpenPGP reader met a construct outside the one profile it accepts
    (v4, ECDSA over NIST P-256, SHA-256, binary signatures, old-format packet headers) or
    bytes that are not a well-formed packet stream. Every such input is refused; the
    reader never guesses."""


class NodeListSignatureError(NodeListError):
    """A signature by an allowed key does not verify, or the key list is not signed by
    the anchor. One bad signature rejects the whole file, as the publisher's rules say."""


class NodeListThresholdError(NodeListError):
    """Fewer distinct custodians signed the node list than the key list's ``threshold``,
    or that ``threshold`` is below the caller's ``min_threshold``."""


class NodeListRollback(NodeListError):
    """A version is below its shipped floor or lower than the last accepted one, equal to
    it with different bytes, or the node list needs a newer key list than the one given
    (``keysVersion`` above the key list's own ``version``)."""


class NodeListExpired(NodeListError):
    """``now`` is at or after the list's ``expires``. Raised by the verifier, and reused
    by a client built from a verified list when it is asked to work past that instant."""


class NodeListNotYetValid(NodeListError):
    """The list's ``issued`` is more than 300 seconds after ``now``: a wrong clock on one
    side, or a list from the future."""


class NodeListStale(NodeListError):
    """The list's ``issued`` is older than ``now`` minus the caller's ``max_age``."""


class NodeListEnvironmentMissing(NodeListError):
    """The verified list holds no node for the requested environment."""


class NodeClientConfigError(EbsiError, ValueError):
    """A node-bound client cannot be built or used as asked: a result that is not the
    verifier's (or whose nodes are not bare origins of its environment), an injected clock that
    does not return a ``datetime``, a selection policy whose output names a node that is not
    in the result, a ``valid_until`` / ``clock`` pair with only one half, or an argument of
    :func:`openvc_ebsi.node_client.for_nodes` that is out of range.

    It is also a :class:`ValueError`, like :class:`UnknownEbsiEnvironment`: this is
    construction-time misuse (or an injected callable misbehaving), never wire input, and
    ``except ValueError`` keeps working. Code that compares the exact class must compare this
    one. It is raised before any socket is opened and before any ``httpx.Client`` exists."""
