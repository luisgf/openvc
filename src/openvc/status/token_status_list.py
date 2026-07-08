"""
openvc.status.token_status_list — IETF Token Status List
(draft-ietf-oauth-status-list-21; IESG-approved and in the RFC Editor queue as of
2026-07, intended Proposed Standard — no RFC number yet). The codec is pinned
byte-for-byte to the draft §4.1 examples in ``tests/test_conformance_status_list``.

The second status-list encoding, alongside the W3C Bitstring list in
``openvc.status.bitstring``. The differences that matter:

* **Multi-bit statuses.** Each referenced token gets ``bits`` in {1, 2, 4, 8},
  so a status is a value (0-255, constrained by ``bits``), not just a set/clear
  bit. ``0x00`` = VALID, ``0x01`` = INVALID (revoked), ``0x02`` = SUSPENDED; the
  rest are application-specific.
* **LSB-first packing.** Index 0 occupies the *lowest* ``bits`` bits of byte 0
  (the W3C list is MSB-first); index 1 the next ``bits`` up, and so on.
* **DEFLATE/zlib** compression (the W3C list uses gzip).

A referenced token points at a status list with a ``status`` claim
``{"status_list": {"idx": N, "uri": "..."}}``; the status list token at that URI
carries ``{"status_list": {"bits": B, "lst": "<base64url zlib>"}}``. As with the
W3C flow, resolving and *verifying* that token (its proof and the SSRF policy for
its host) is the caller's concern — injected as ``resolve_status_list_token`` —
so this module stays pure stdlib and proof-agnostic.
"""
from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from ..observability import logger, span
from ._decompress import DecompressionBomb, inflate_bounded
from .bitstring import StatusListError

# IETF status values (draft-ietf-oauth-status-list, "Status Types").
STATUS_VALID = 0x00
STATUS_INVALID = 0x01        # permanently invalid — "revoked"
STATUS_SUSPENDED = 0x02      # temporarily invalid — "suspended"

_VALID_BITS = frozenset({1, 2, 4, 8})


def _check_bits(bits: int) -> None:
    if bits not in _VALID_BITS:
        raise StatusListError(f"bits must be one of 1, 2, 4, 8; got {bits!r}")


# --------------------------------------------------------------------------- #
# codec — the packed multi-bit list
# --------------------------------------------------------------------------- #

def decode_status_list(lst: str) -> bytes:
    """base64url-decode then zlib-inflate a ``lst`` value into the packed bytes."""
    try:
        compressed = base64.urlsafe_b64decode(lst + "=" * (-len(lst) % 4))
    except (ValueError, TypeError) as exc:
        raise StatusListError(f"lst is not valid base64url: {exc}") from exc
    try:
        return inflate_bounded(compressed)
    except zlib.error as exc:
        raise StatusListError(f"lst is not valid zlib/DEFLATE: {exc}") from exc
    except DecompressionBomb as exc:
        raise StatusListError(f"lst decompresses too large: {exc}") from exc


def encode_status_list(data: bytes) -> str:
    """zlib-deflate then base64url (unpadded) — the inverse of
    :func:`decode_status_list`, for issuers and tests. zlib output is
    deterministic for a fixed level, so no mtime dance is needed."""
    return base64.urlsafe_b64encode(zlib.compress(data, 9)).rstrip(b"=").decode("ascii")


def new_status_list(size: int, *, bits: int = 1) -> bytearray:
    """A zeroed (all-VALID) packed list holding at least *size* statuses of
    *bits* each."""
    _check_bits(bits)
    if size < 0:
        raise StatusListError(f"size must be non-negative, got {size}")
    per_byte = 8 // bits
    return bytearray((size + per_byte - 1) // per_byte)


def get_status(data: bytes, index: int, *, bits: int = 1) -> int:
    """Return the status value at *index* for a list packed *bits* per status
    (LSB-first). Raises for a bad *bits* or an out-of-range index."""
    _check_bits(bits)
    if index < 0:
        raise StatusListError(f"status index must be non-negative, got {index}")
    per_byte = 8 // bits
    byte_index, pos = divmod(index, per_byte)
    if byte_index >= len(data):
        raise StatusListError(
            f"status index {index} out of range for a {len(data) * per_byte}-status list")
    mask = (1 << bits) - 1
    return (data[byte_index] >> (pos * bits)) & mask


def set_status(data: bytearray, index: int, value: int, *, bits: int = 1) -> None:
    """Set the status value at *index* in-place (LSB-first). For issuers and
    tests. Raises if *value* does not fit in *bits*."""
    _check_bits(bits)
    if index < 0:
        raise StatusListError(f"status index must be non-negative, got {index}")
    mask = (1 << bits) - 1
    if not 0 <= value <= mask:
        raise StatusListError(f"status value {value} does not fit in {bits} bit(s)")
    per_byte = 8 // bits
    byte_index, pos = divmod(index, per_byte)
    if byte_index >= len(data):
        raise StatusListError(
            f"status index {index} out of range for a {len(data) * per_byte}-status list")
    shift = pos * bits
    data[byte_index] = (data[byte_index] & ~(mask << shift)) | (value << shift)


# --------------------------------------------------------------------------- #
# referenced-token status check
# --------------------------------------------------------------------------- #

# Resolve a status-list-token URI -> that token's VERIFIED claims (a dict with a
# "status_list": {"bits", "lst"} member). Verifying the token's signature and the
# SSRF policy for its host are the caller's concern, as with the W3C flow.
ResolveStatusListToken = Callable[[str], dict]
# The async counterpart: the same, returning an awaitable.
AsyncResolveStatusListToken = Callable[[str], Awaitable[dict]]


@dataclass(frozen=True)
class TokenStatusRef:
    uri: str        # the status list token URI
    index: int      # this token's position in the list


@dataclass(frozen=True)
class TokenStatusResult:
    ref: TokenStatusRef
    status: int         # the raw status value (0-255)
    revoked: bool       # status == INVALID (0x01)
    suspended: bool     # status == SUSPENDED (0x02)


def parse_token_status_ref(claims: dict[str, Any]) -> TokenStatusRef | None:
    """Parse a referenced token's ``status.status_list`` reference, or ``None`` if
    the token carries no status-list reference. Raises on a malformed reference."""
    status = claims.get("status")
    if not isinstance(status, dict):
        return None
    ref = status.get("status_list")
    if not isinstance(ref, dict):
        return None
    uri = ref.get("uri")
    idx = ref.get("idx")
    if not uri or idx is None:
        raise StatusListError("status_list reference needs both uri and idx")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        raise StatusListError(
            f"status_list idx must be a non-negative integer, got {idx!r}")
    return TokenStatusRef(uri=str(uri), index=idx)


def _status_list_claim(token_claims: dict[str, Any]) -> tuple[int, str]:
    sl = token_claims.get("status_list")
    if not isinstance(sl, dict):
        raise StatusListError("status list token has no status_list claim")
    bits = sl.get("bits")
    lst = sl.get("lst")
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise StatusListError(f"status_list.bits must be an integer, got {bits!r}")
    if not isinstance(lst, str):
        raise StatusListError("status_list.lst must be a base64url string")
    return bits, lst


def _token_status_result(
    ref: TokenStatusRef, token_claims: dict[str, Any]
) -> TokenStatusResult:
    """Decode a resolved status-list token and read this token's status (pure —
    shared by the sync and async checks)."""
    bits, lst = _status_list_claim(token_claims)
    value = get_status(decode_status_list(lst), ref.index, bits=bits)
    result = TokenStatusResult(
        ref=ref,
        status=value,
        revoked=value == STATUS_INVALID,
        suspended=value == STATUS_SUSPENDED,
    )
    logger.debug("token status checked: revoked=%s suspended=%s",
                 result.revoked, result.suspended)
    return result


def check_token_status(
    claims: dict[str, Any], *, resolve_status_list_token: ResolveStatusListToken
) -> TokenStatusResult | None:
    """Resolve the status list token a referenced token points at and read its
    status.

    Returns ``None`` if the token carries no status-list reference. Never raises
    on a non-VALID status — turning INVALID/SUSPENDED into a hard failure is the
    verifier's policy — only on malformed data or a resolve failure.
    """
    ref = parse_token_status_ref(claims)
    if ref is None:
        return None
    with span("openvc.status"):
        token_claims = resolve_status_list_token(ref.uri)
        return _token_status_result(ref, token_claims)


async def check_token_status_async(
    claims: dict[str, Any], *, resolve_status_list_token: AsyncResolveStatusListToken
) -> TokenStatusResult | None:
    """Async :func:`check_token_status` — awaits an async ``resolve_status_list_token``;
    identical decoding and fail-closed semantics (the status-reading is the same
    pure code)."""
    ref = parse_token_status_ref(claims)
    if ref is None:
        return None
    with span("openvc.status"):
        token_claims = await resolve_status_list_token(ref.uri)
        return _token_status_result(ref, token_claims)


__all__ = [
    "AsyncResolveStatusListToken",
    "ResolveStatusListToken",
    "STATUS_INVALID",
    "STATUS_SUSPENDED",
    "STATUS_VALID",
    "TokenStatusRef",
    "TokenStatusResult",
    "check_token_status",
    "check_token_status_async",
    "decode_status_list",
    "encode_status_list",
    "get_status",
    "new_status_list",
    "parse_token_status_ref",
    "set_status",
]
