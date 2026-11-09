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
import zlib

from ..errors import OpenvcError
from ._decompress import DecompressionBomb, gunzip_bounded


class StatusListError(OpenvcError):
    """The encodedList could not be decoded, or an index is out of range."""


# The index/size rule lives in ``_index``, which imports ``StatusListError`` from this
# module; the helpers are therefore imported inside the functions that need them.

def new_bitstring(size: int, status_size: int = 1) -> bytearray:
    """A zeroed bitstring (every status clear) with room for at least *size*
    statuses of *status_size* bits each (1..8, default 1) — the issuer-side counterpart to
    :func:`openvc.status.token_status_list.new_status_list`.

    *size* is an ``int`` (never a ``bool`` or ``float``) of at most
    :data:`~openvc.status._index.MAX_STATUS_INDEX`, the most statuses a list openvc
    decodes can hold (``MAX_STATUS_INDEX // status_size`` at a wider status); otherwise
    :class:`StatusListError`."""
    from ._index import packed_length, plain_int, status_size as _check_size
    width = _check_size(status_size, field="status_size")
    packed_length(size, per_byte=8)          # *size* is an int, before it is multiplied
    return bytearray(packed_length(plain_int(size) * width, per_byte=8, field="size"))


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
    # a valid gzip header over corrupt DEFLATE data raises zlib.error, not OSError
    except (OSError, EOFError, zlib.error) as exc:
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
    """Return the bit (0/1) at *index*, MSB-first. *index* is an ``int`` (a ``bool`` or
    ``float`` is refused, not read as some other bit); :class:`StatusListError` for a
    bad or out-of-range one."""
    from ._index import locate_status
    byte_index, bit_index = locate_status(index, per_byte=8, length=len(bits), unit="bit")
    return (bits[byte_index] >> (7 - bit_index)) & 1


def get_status_value(bits: bytes, index: int, size: int = 1) -> int:
    """Return the *size*-bit status of entry *index* (Bitstring Status List v1.0 §3.2
    step 10): bits ``index * size`` to ``index * size + size - 1``, MSB-first, the first
    bit read being the most significant of the value. *size* is 1..8 (``1`` is
    :func:`get_status_bit`). :class:`StatusListError` for a bad *index* or *size*, or when
    the last bit lies past the list."""
    from ._index import status_index, status_size
    size = status_size(size, field="status size")
    index = status_index(index, field="status index", allow_string=False, capped=False)
    first = index * size
    if first + size > len(bits) * 8:
        raise StatusListError(
            f"status index {index} (statusSize {size}) out of range for a "
            f"{len(bits) * 8}-bit list")
    value = 0
    for pos in range(first, first + size):
        value = (value << 1) | ((bits[pos >> 3] >> (7 - (pos & 7))) & 1)
    return value


def set_status_value(bits: bytearray, index: int, value: int, size: int = 1) -> None:
    """Write the *size*-bit status *value* of entry *index* in-place (the inverse of
    :func:`get_status_value`; for issuers and tests). *value* is an ``int`` in
    ``0 .. 2**size - 1``, never a ``bool``; :class:`StatusListError` otherwise, or for a
    bad *index* / *size* or one past the list."""
    from ._index import plain_int, status_index, status_size, brief
    size = status_size(size, field="status size")
    index = status_index(index, field="status index", allow_string=False, capped=False)
    if not isinstance(value, int) or isinstance(value, bool):
        raise StatusListError(f"status value must be an integer, got {brief(value)}")
    value = plain_int(value)
    if not 0 <= value < 2 ** size:
        raise StatusListError(
            f"status value {brief(value)} does not fit statusSize {size}")
    first = index * size
    if first + size > len(bits) * 8:
        raise StatusListError(
            f"status index {index} (statusSize {size}) out of range for a "
            f"{len(bits) * 8}-bit list")
    for offset in range(size):
        pos = first + offset
        mask = 1 << (7 - (pos & 7))
        if (value >> (size - 1 - offset)) & 1:
            bits[pos >> 3] |= mask
        else:
            bits[pos >> 3] &= ~mask


def set_status_bit(bits: bytearray, index: int, value: int) -> None:
    """Set/clear the bit at *index* (MSB-first) in-place. For issuers and tests.
    *index* is held to the same rule as :func:`get_status_bit`. *value* is read for its
    truthiness, as it always was: a truthy one sets the bit, a falsy one clears it (only
    :func:`~openvc.status.token_status_list.set_status` insists on an ``int``)."""
    from ._index import locate_status
    byte_index, bit_index = locate_status(index, per_byte=8, length=len(bits), unit="bit")
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
    "get_status_value",
    "new_bitstring",
    "set_status_bit",
    "set_status_value",
]
