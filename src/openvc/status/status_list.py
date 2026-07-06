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
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..errors import OpenvcError
from .bitstring import decode_bitstring, get_status_bit

# Fetch+verify a status-list credential URL -> the status-list VC as a dict.
ResolveStatusList = Callable[[str], dict]

_ENTRY_TYPES = frozenset({"BitstringStatusListEntry", "StatusList2021Entry"})
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
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    from .bitstring import StatusListError
    raise StatusListError("credentialStatus must be an object or an array")


def parse_status_entries(credential: dict[str, Any]) -> list[StatusEntry]:
    """Parse the credential's ``credentialStatus`` into typed entries. Entries
    whose type is not a recognised status-list entry are skipped (a credential
    may carry unrelated status types)."""
    from .bitstring import StatusListError
    entries: list[StatusEntry] = []
    for raw in _as_entry_list(credential.get("credentialStatus")):
        types = raw.get("type", [])
        types = [types] if isinstance(types, str) else types
        if not _ENTRY_TYPES.intersection(types):
            continue
        url = raw.get("statusListCredential")
        index = raw.get("statusListIndex")
        if not url or index is None:
            raise StatusListError(
                "status entry needs statusListCredential and statusListIndex")
        try:
            index_int = int(index)         # the spec encodes the index as a string
        except (TypeError, ValueError) as exc:
            raise StatusListError(f"invalid statusListIndex {index!r}") from exc
        entries.append(StatusEntry(
            status_list_credential=str(url),
            index=index_int,
            purpose=raw.get("statusPurpose", PURPOSE_REVOCATION),
            entry_type=next(iter(_ENTRY_TYPES.intersection(types))),
        ))
    return entries


def _encoded_list(status_vc: dict[str, Any], entry: StatusEntry) -> str:
    from .bitstring import StatusListError
    subject = status_vc.get("credentialSubject")
    if not isinstance(subject, dict):
        raise StatusListError("status-list credential has no credentialSubject")
    # If the list declares a purpose, it must match the entry that points at it.
    list_purpose = subject.get("statusPurpose")
    if list_purpose and list_purpose != entry.purpose:
        raise StatusListError(
            f"status-list purpose {list_purpose!r} != entry purpose {entry.purpose!r}")
    encoded = subject.get("encodedList")
    if not encoded:
        raise StatusListError("status-list credentialSubject has no encodedList")
    return str(encoded)


def check_credential_status(
    credential: dict[str, Any], *, resolve_status_list: ResolveStatusList
) -> StatusResult:
    """Resolve each status-list credential the credential references and read its
    bit. Returns a :class:`StatusResult`; never raises on a *set* bit (that is a
    verifier policy decision) — only on malformed data or a resolve failure."""
    results: list[StatusEntryResult] = []
    revoked = suspended = False
    for entry in parse_status_entries(credential):
        status_vc = resolve_status_list(entry.status_list_credential)
        bits = decode_bitstring(_encoded_list(status_vc, entry))
        is_set = bool(get_status_bit(bits, entry.index))
        results.append(StatusEntryResult(entry=entry, is_set=is_set))
        if is_set and entry.purpose == PURPOSE_REVOCATION:
            revoked = True
        elif is_set and entry.purpose == PURPOSE_SUSPENSION:
            suspended = True
    return StatusResult(revoked=revoked, suspended=suspended, entries=tuple(results))


__all__ = [
    "CredentialRevoked",
    "CredentialSuspended",
    "ResolveStatusList",
    "StatusEntry",
    "StatusEntryResult",
    "StatusResult",
    "check_credential_status",
    "parse_status_entries",
]
