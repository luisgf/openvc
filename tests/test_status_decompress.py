"""
tests/test_status_decompress.py — bounded status-list decompression (issue #2).

A malicious/compromised issuer controls the compressed `encodedList` / `lst`, and
status decode is fed by a caller-injected resolver that `openvc.fetch`'s wire cap
never reaches — so decode must bound the *decompressed* size and fail closed rather
than inflate a compression bomb into an OOM.
"""
from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from openvc.status.bitstring import (
    StatusListError,
    decode_bitstring,
    encode_bitstring,
)
from openvc.status.token_status_list import decode_status_list, encode_status_list
from openvc.status._decompress import (
    DecompressionBomb,
    gunzip_bounded,
    inflate_bounded,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# the bounded helpers (fast: tiny explicit cap, no large allocation)
# --------------------------------------------------------------------------- #

def test_gunzip_roundtrip_under_cap():
    assert gunzip_bounded(gzip.compress(b"hello world")) == b"hello world"


def test_inflate_roundtrip_under_cap():
    assert inflate_bounded(zlib.compress(b"hello world")) == b"hello world"


def test_gunzip_bounded_rejects_over_cap():
    payload = gzip.compress(b"A" * 100_000)
    with pytest.raises(DecompressionBomb):
        gunzip_bounded(payload, max_out=1000)


def test_inflate_bounded_rejects_over_cap():
    payload = zlib.compress(b"A" * 100_000)
    with pytest.raises(DecompressionBomb):
        inflate_bounded(payload, max_out=1000)


def test_bounded_helpers_return_exactly_at_cap():
    # output length == max_out must be accepted (one byte more is the bomb boundary)
    data = b"A" * 5000
    assert gunzip_bounded(gzip.compress(data), max_out=5000) == data
    assert inflate_bounded(zlib.compress(data), max_out=5000) == data


# --------------------------------------------------------------------------- #
# codec-level: a real bomb over the 16 MiB default ceiling -> StatusListError
# --------------------------------------------------------------------------- #

_OVER_CAP = b"\x00" * (20 * 1024 * 1024)   # 20 MiB inflated, ~20 KiB compressed


def test_decode_bitstring_rejects_gzip_bomb():
    bomb = _b64u(gzip.compress(_OVER_CAP))
    assert len(bomb) < 200_000                       # tiny on the wire
    with pytest.raises(StatusListError):
        decode_bitstring(bomb)


def test_decode_status_list_rejects_zlib_bomb():
    bomb = _b64u(zlib.compress(_OVER_CAP))
    with pytest.raises(StatusListError):
        decode_status_list(bomb)


# --------------------------------------------------------------------------- #
# no regression: legitimate lists still round-trip through the codecs
# --------------------------------------------------------------------------- #

def test_codec_roundtrip_unbroken():
    bits = bytes(range(256)) * 64                    # 16 KiB, well under the cap
    assert decode_bitstring(encode_bitstring(bits)) == bits
    assert decode_status_list(encode_status_list(bits)) == bits
