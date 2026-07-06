"""
openvc.multibase — base58btc multibase ('z') and multicodec varint helpers.

Used by the Data Integrity proof suite (proofValue = ``z`` + base58btc(sig)) and
handy for decoding did:key / multibase key material. Pure stdlib.
"""
from __future__ import annotations

from .errors import OpenvcError

# base58btc (Bitcoin) alphabet.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


class MultibaseError(OpenvcError):
    """Malformed multibase / base58 / varint input."""


def b58btc_decode(s: str) -> bytes:
    """Decode a base58btc string to bytes (leading '1's map to leading NUL)."""
    num = 0
    for ch in s:
        try:
            num = num * 58 + _B58_INDEX[ch]
        except KeyError:
            raise MultibaseError(f"invalid base58 character {ch!r}") from None
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    n_leading = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_leading + body


def b58btc_encode(data: bytes) -> str:
    """Encode bytes as base58btc (leading NUL bytes map to leading '1')."""
    num = int.from_bytes(data, "big")
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(_B58[rem])
    n_leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * n_leading + "".join(reversed(chars))


def decode_multibase(value: str) -> bytes:
    """Decode a base58btc multibase value (must start with 'z')."""
    if not value.startswith("z"):
        raise MultibaseError(f"unsupported multibase prefix in {value[:1]!r} (want 'z')")
    return b58btc_decode(value[1:])


def encode_multibase(data: bytes) -> str:
    """Encode bytes as a base58btc multibase value (prefixed 'z')."""
    return "z" + b58btc_encode(data)


def read_varint(data: bytes) -> tuple[int, int]:
    """Read an unsigned LEB128 varint from the front of *data*.

    Returns (value, n_bytes_consumed) — e.g. to strip a multicodec prefix.
    """
    result = shift = 0
    for i, byte in enumerate(data):
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i + 1
        shift += 7
    raise MultibaseError("truncated multicodec varint")


__all__ = [
    "MultibaseError",
    "b58btc_decode",
    "b58btc_encode",
    "decode_multibase",
    "encode_multibase",
    "read_varint",
]
