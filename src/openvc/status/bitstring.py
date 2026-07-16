"""
openvc.status.bitstring — the W3C Bitstring Status List bit encoding.

A status list is a bitstring where each credential owns one bit; a set bit means
the status applies (revoked / suspended, per the list's statusPurpose). On the
wire the bitstring is **GZIP-compressed, base64url-encoded, then multibase-prefixed**
(``u``) — the ``encodedList``. The W3C v1.0 REC mandates the multibase form;
:func:`decode_bitstring` also tolerates a legacy prefix-less value.

Bit order (the classic thing to get wrong): most-significant-bit first — index 0
is the top bit (0x80) of byte 0, index 7 the bottom bit of byte 0, index 8 the
top bit of byte 1, and so on. This matches the W3C Bitstring Status List and
StatusList2021 encodings.

Pure stdlib (base64 + gzip): no dependency, usable by any VC profile.
"""
from __future__ import annotations

import base64
import gzip

from ..errors import OpenvcError
from ._decompress import DecompressionBomb, gunzip_bounded


class StatusListError(OpenvcError):
    """The encodedList could not be decoded, or an index is out of range."""


def new_bitstring(size: int) -> bytearray:
    """A zeroed bitstring (every status clear) with room for at least *size*
    single-bit statuses — the issuer-side counterpart to
    :func:`openvc.status.token_status_list.new_status_list`."""
    if size < 0:
        raise StatusListError(f"size must be non-negative, got {size}")
    return bytearray((size + 7) // 8)


def decode_bitstring(encoded_list: str) -> bytes:
    """Decode an ``encodedList`` (optional multibase prefix, base64url, GZIP) into raw bits.

    The W3C Bitstring Status List v1.0 REC mandates the ``encodedList`` be a
    **multibase-encoded** base64url value — i.e. prefixed with ``u`` — so every
    spec-conformant list (and real third-party producers) carry that ``u``. A leading
    ``u`` is stripped before base64url-decoding; a raw gzip stream base64url-encodes
    to ``H4sI…`` (never ``u``), so bare, legacy (pre-multibase) lists still decode
    unchanged and there is no ambiguity."""
    if encoded_list[:1] == "u":                       # multibase base64url (the REC form)
        encoded_list = encoded_list[1:]
    try:
        compressed = base64.urlsafe_b64decode(
            encoded_list + "=" * (-len(encoded_list) % 4))
    except (ValueError, TypeError) as exc:
        raise StatusListError(f"encodedList is not valid base64url: {exc}") from exc
    try:
        return gunzip_bounded(compressed)
    except (OSError, EOFError) as exc:
        raise StatusListError(f"encodedList is not valid gzip: {exc}") from exc
    except DecompressionBomb as exc:
        raise StatusListError(f"encodedList decompresses too large: {exc}") from exc


def encode_bitstring(bits: bytes) -> str:
    """GZIP, base64url (unpadded), then the multibase ``u`` prefix — the inverse of
    :func:`decode_bitstring`, for issuers and tests. The W3C REC mandates a
    **multibase-encoded** ``encodedList`` (leading ``u``); emitting it keeps openvc's
    own issued lists spec-conformant. ``mtime=0`` keeps the output deterministic."""
    compressed = gzip.compress(bits, mtime=0)
    return "u" + base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


def get_status_bit(bits: bytes, index: int) -> int:
    """Return the bit (0/1) at *index*, MSB-first. Raises for out-of-range."""
    if index < 0:
        raise StatusListError(f"status index must be non-negative, got {index}")
    byte_index, bit_index = divmod(index, 8)
    if byte_index >= len(bits):
        raise StatusListError(
            f"status index {index} out of range for a {len(bits) * 8}-bit list")
    return (bits[byte_index] >> (7 - bit_index)) & 1


def set_status_bit(bits: bytearray, index: int, value: int) -> None:
    """Set/clear the bit at *index* (MSB-first) in-place. For issuers and tests."""
    if index < 0:
        raise StatusListError(f"status index must be non-negative, got {index}")
    byte_index, bit_index = divmod(index, 8)
    if byte_index >= len(bits):
        raise StatusListError(
            f"status index {index} out of range for a {len(bits) * 8}-bit list")
    mask = 1 << (7 - bit_index)
    if value:
        bits[byte_index] |= mask
    else:
        bits[byte_index] &= ~mask


__all__ = [
    "StatusListError",
    "decode_bitstring",
    "encode_bitstring",
    "get_status_bit",
    "new_bitstring",
    "set_status_bit",
]
