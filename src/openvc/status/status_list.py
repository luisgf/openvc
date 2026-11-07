"""
openvc.status.status_list — check a credential's ``credentialStatus`` against a
Bitstring Status List credential.

Transport- and proof-agnostic by design: the caller injects
``resolve_status_list`` — a function that fetches the status-list credential URL
and returns the **verified** status-list VC as a dict (its signature is the
caller's concern, since the proof format and the SSRF policy for that host are
too). This module then parses the entry, decodes the bitstring, and reads the
bit. So it stays pure stdlib and reusable by any VC profile (OB 3.0, EBSI, EUDI).

Supports ``BitstringStatusListEntry`` and the older ``StatusList2021Entry`` —
same field names, same bit encoding.

The resolved list is **bound to the entry that named it** before its bit is read: its
``type`` and ``credentialSubject.type`` must be the ones of the entry's family
(``BitstringStatusListCredential`` / ``BitstringStatusList`` for a
``BitstringStatusListEntry``, the ``StatusList2021`` spellings for a
``StatusList2021Entry``; Bitstring Status List v1.0 §2.1, §2.2), and its ``id``, when it
carries one, must equal the entry's ``statusListCredential``. A verified list the issuer
published at another URL, or any issuer-signed credential whose subject happens to carry
an ``encodedList``, is refused with :class:`~openvc.status.bitstring.StatusListError`
whoever serves it. A list with no ``id`` is bound by its issuer (ADR-0006, when the
binding is on) and its types only; the default resolvers surface a VC-JWT list's ``jti``
as its ``id`` so the VCDM 1.1 JWT encoding is bound too.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from ..errors import OpenvcError
from ..observability import logger, span
from ..proof._verify_common import own_identifier
from ._index import brief, status_index
from .bitstring import decode_bitstring, get_status_bit

# Fetch+verify a status-list credential URL -> the status-list VC as a dict. A custom
# resolver MUST return the body :func:`openvc.resolvers.authenticated_status_list` gives for
# the ``VerificationResult`` of the list, not ``result.credential`` as it is: that helper
# fills in the authenticated ``issuer`` where the body names no one (#226) and the ``id`` a
# VC-JWT list carries only in ``jti`` (#377), both on a copy. Without it the issuer binding
# fails closed and the id binding below is left to the body alone, so a VCDM 1.1 VC-JWT list
# reaches the check id-less. The blessed resolvers in :mod:`openvc.resolvers` do this.
ResolveStatusList = Callable[[str], dict]
# The async counterpart: the same, returning an awaitable.
AsyncResolveStatusList = Callable[[str], Awaitable[dict]]

_ENTRY_TYPES = frozenset({"BitstringStatusListEntry", "StatusList2021Entry"})
# The list a status entry may read, by the entry's type: the credential `type` and the
# `credentialSubject.type` the list must carry (Bitstring Status List v1.0 §2.1 / §2.2; the
# older StatusList2021 draft for the legacy entry). An entry of one family never reads a
# list of the other.
_LIST_TYPES: dict[str, tuple[str, str]] = {
    "BitstringStatusListEntry": ("BitstringStatusListCredential", "BitstringStatusList"),
    "StatusList2021Entry": ("StatusList2021Credential", "StatusList2021"),
}
PURPOSE_REVOCATION = "revocation"
PURPOSE_SUSPENSION = "suspension"


class CredentialRevoked(OpenvcError):
    """Raised by verifiers that treat a set revocation bit as a hard failure."""


class CredentialSuspended(OpenvcError):
    """Raised by verifiers that treat a set suspension bit as a hard failure
    (a suspended credential is temporarily invalid — not currently usable)."""


@dataclass(frozen=True)
class StatusEntry:
    status_list_credential: str    # URL of the status-list VC
    index: int                     # this credential's bit position
    purpose: str                   # "revocation" | "suspension" | ...
    entry_type: str


@dataclass(frozen=True)
class StatusEntryResult:
    entry: StatusEntry
    is_set: bool                   # True if the bit is set (status applies)


@dataclass(frozen=True)
class StatusResult:
    revoked: bool                  # any revocation-purpose bit set
    suspended: bool                # any suspension-purpose bit set
    entries: tuple[StatusEntryResult, ...]


def _as_entry_list(raw: Any) -> list[dict]:
    from .bitstring import StatusListError
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        # Fail closed on any non-object member rather than filter it away. JSON-LD
        # expansion flattens an array nested in an array, so an RDF-signed credential
        # signs [S1, [S2]] exactly as [S1, S2]: dropping the inner array skipped S2's
        # revocation bit, and [[S]] left no entry at all (GHSA-h9rq-wxcw-4rjc).
        if not all(isinstance(e, dict) for e in raw):
            raise StatusListError("credentialStatus entries must be objects")
        return list(raw)
    raise StatusListError("credentialStatus must be an object or an array")


def parse_status_entries(credential: dict[str, Any]) -> list[StatusEntry]:
    """Parse the credential's ``credentialStatus`` into typed entries. Entries
    whose type is not a recognised status-list entry are skipped (a credential
    may carry unrelated status types); a member that is not an object at all (an
    array, a string reference, ``null``) or an object with no ``type`` raises
    :class:`~openvc.status.bitstring.StatusListError` instead, since its entries
    could not be read."""
    from .bitstring import StatusListError
    entries: list[StatusEntry] = []
    for raw in _as_entry_list(credential.get("credentialStatus")):
        types = raw.get("type")
        if types is None or types == "" or types == []:
            # VCDM requires a type on every status entry, so an object without one is
            # not an unrelated status type to skip: it is a node reference ({"id": X},
            # which JSON-LD signs exactly as the bare X), and RDF lets the entry it names
            # be described under another property of the credential. Skipping it hid
            # that entry's revocation bit (GHSA-h9rq-wxcw-4rjc), as credentialSchema's
            # "entry needs a type" already prevented.
            raise StatusListError("credentialStatus entry needs a type")
        if isinstance(types, str):
            types = [types]
        elif not isinstance(types, (list, tuple)):
            types = []
        # Only string members can name a status-entry type; filtering them keeps a hostile
        # `type` (a non-iterable, or a list carrying an unhashable/dict member) from crashing
        # the set intersection with a bare TypeError — it is skipped like any unrelated type.
        matched = _ENTRY_TYPES.intersection(t for t in types if isinstance(t, str))
        if not matched:
            continue
        url = raw.get("statusListCredential")
        index = raw.get("statusListIndex")
        if not url or index is None:
            raise StatusListError(
                "status entry needs statusListCredential and statusListIndex")
        # Never str() a hostile value: a deeply nested array overflows the stack with a
        # bare RecursionError, and an int or object would become a garbage URL.
        if not isinstance(url, str):
            raise StatusListError(
                f"statusListCredential must be a URL string, got {brief(url)}")
        purpose = raw.get("statusPurpose", PURPOSE_REVOCATION)
        if not isinstance(purpose, str):   # an explicit null would match no purpose
            raise StatusListError(f"statusPurpose must be a string, got {brief(purpose)}")
        entries.append(StatusEntry(
            status_list_credential=url,
            # the spec encodes the index as a base-10 string; a JSON integer is
            # tolerated, a float / bool / signed or non-ASCII string is not
            index=status_index(index, field="statusListIndex", allow_string=True),
            purpose=purpose,
            # deterministic for an entry that carries both recognised types (set order is
            # per-process): the list it reads is decided by this type
            entry_type=min(matched),
        ))
    return entries


def _encoded_list(status_vc: dict[str, Any], entry: StatusEntry) -> str:
    from .bitstring import StatusListError
    if not isinstance(status_vc, dict):     # a caller's resolver returned something else
        raise StatusListError(
            f"resolved status-list credential must be an object, got {brief(status_vc)}")
    subject = status_vc.get("credentialSubject")
    if not isinstance(subject, dict):
        raise StatusListError("status-list credential has no credentialSubject")
    # If the list declares a purpose, it must match the entry that points at it.
    list_purpose = subject.get("statusPurpose")
    if list_purpose and list_purpose != entry.purpose:
        raise StatusListError(
            f"status-list purpose {brief(list_purpose)} != entry purpose {brief(entry.purpose)}")
    encoded = subject.get("encodedList")
    if not isinstance(encoded, str) or not encoded:
        raise StatusListError("status-list credentialSubject has no encodedList string")
    # The list must be a status list of the entry's family, by both types the REC makes
    # MUSTs (§2.1 `type`, §2.2 `credentialSubject.type`): an issuer-signed credential of any
    # other type whose subject carries an `encodedList` is not a status list, however it is
    # served. A `type` that is neither a string nor an array names no type.
    list_type, subject_type = _LIST_TYPES[entry.entry_type]
    if list_type not in _type_names(status_vc.get("type")):
        raise StatusListError(
            f"status-list credential for a {entry.entry_type} needs type {list_type}, "
            f"got {brief(status_vc.get('type'))}")
    if subject_type not in _type_names(subject.get("type")):
        raise StatusListError(
            f"status-list credentialSubject for a {entry.entry_type} needs type "
            f"{subject_type}, got {brief(subject.get('type'))}")
    # The list must be the one the entry named: its `id` is the URL the entry pointed at.
    # The issuer binding (ADR-0006) proves who signed the list, not which list it is, so
    # another list of the same issuer served at this URL cleared a revocation. A list with
    # no `id` is the documented residual (bound by issuer and types only); a present `id`
    # that is not a string is malformed, never "no id". Compared as strings, unnormalised.
    # Either JSON-LD spelling names the list (`id` or `@id`; both and different is malformed).
    present, list_id = own_identifier(status_vc, error=StatusListError)
    if present:
        if not isinstance(list_id, str):
            raise StatusListError(
                f"status-list credential id must be a string, got {brief(list_id)}")
        if list_id != entry.status_list_credential:
            raise StatusListError(
                f"status-list credential id {brief(list_id)} is not the entry's "
                f"statusListCredential {brief(entry.status_list_credential)}")
    return encoded


def _type_names(raw: Any) -> set[str]:
    """The type names a ``type`` value carries: the string itself, or the string members
    of an array (a member that is no string names nothing, as in
    :func:`parse_status_entries`). Any other shape — absent, ``null``, a number, an
    object — names no type at all, so the list is refused by the membership test rather
    than crashing it or passing as untyped."""
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, (list, tuple)):
        return {t for t in raw if isinstance(t, str)}
    return set()


def _read_status_bit(status_vc: dict[str, Any], entry: StatusEntry) -> StatusEntryResult:
    """Decode a resolved status-list VC and read this entry's bit (pure — shared by
    the sync and async checks)."""
    bits = decode_bitstring(_encoded_list(status_vc, entry))
    return StatusEntryResult(entry=entry, is_set=bool(get_status_bit(bits, entry.index)))


def _tally_status(results: list[StatusEntryResult]) -> StatusResult:
    """Fold per-entry results into a :class:`StatusResult` (revoked/suspended if any
    matching-purpose bit is set)."""
    revoked = any(r.is_set and r.entry.purpose == PURPOSE_REVOCATION for r in results)
    suspended = any(r.is_set and r.entry.purpose == PURPOSE_SUSPENSION for r in results)
    logger.debug("status checked: revoked=%s suspended=%s entries=%d",
                 revoked, suspended, len(results))
    return StatusResult(revoked=revoked, suspended=suspended, entries=tuple(results))


def check_credential_status(
    credential: dict[str, Any], *, resolve_status_list: ResolveStatusList
) -> StatusResult:
    """Resolve each status-list credential the credential references and read its
    bit. Returns a :class:`StatusResult`; never raises on a *set* bit (that is a
    verifier policy decision) — only on malformed data, a resolve failure, or a resolved
    list that is not the one the entry named (its types are not the entry family's, or
    its ``id`` is not the entry's ``statusListCredential``). *resolve_status_list* must
    return the body :func:`openvc.resolvers.authenticated_status_list` gives (see
    :data:`ResolveStatusList`)."""
    with span("openvc.status"):
        results = [_read_status_bit(resolve_status_list(e.status_list_credential), e)
                   for e in parse_status_entries(credential)]
    return _tally_status(results)


async def check_credential_status_async(
    credential: dict[str, Any], *, resolve_status_list: AsyncResolveStatusList
) -> StatusResult:
    """Async :func:`check_credential_status` — awaits an async ``resolve_status_list``;
    identical decoding, tally, and fail-closed semantics (the bit-reading is the same
    pure code)."""
    with span("openvc.status"):
        results = [_read_status_bit(await resolve_status_list(e.status_list_credential), e)
                   for e in parse_status_entries(credential)]
    return _tally_status(results)


__all__ = [
    "AsyncResolveStatusList",
    "CredentialRevoked",
    "CredentialSuspended",
    "ResolveStatusList",
    "StatusEntry",
    "StatusEntryResult",
    "StatusResult",
    "check_credential_status",
    "check_credential_status_async",
    "parse_status_entries",
]
