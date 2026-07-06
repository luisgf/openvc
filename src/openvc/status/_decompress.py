"""
openvc.status._decompress — bounded gzip/zlib inflation for status-list decode.

Status-list bytes are fetched from an issuer-named URL through a **caller-injected**
resolver, so ``openvc.fetch``'s 1 MiB wire cap does not protect this path — and even
that cap is on the *compressed* size. gzip/zlib reach ~1000:1 ratios, so a ~1 KB
``encodedList`` / ``lst`` can inflate to gigabytes and OOM the verifier during the
routine revocation check every credential's status dereferences.

These helpers cap the **decompressed** output and fail closed
(:class:`DecompressionBomb`) before materialising it: the gzip path reads the stream
incrementally (`GzipFile.read` never inflates past the ceiling), the zlib path
decompresses in bounded chunks. Pure stdlib.
"""
from __future__ import annotations

import gzip
import io
import zlib

# 16 MiB decompressed ceiling: ~134M 1-bit W3C entries or ~16M 8-bit IETF statuses —
# far beyond any real herd-privacy status list, but well below OOM territory.
MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024

_CHUNK = 65536


class DecompressionBomb(Exception):
    """The decompressed output exceeded the ceiling (a likely compression bomb)."""


def gunzip_bounded(data: bytes, *, max_out: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """GZIP-inflate *data*, refusing to materialise more than *max_out* bytes.

    ``GzipFile.read(max_out + 1)`` decompresses lazily, so a bomb is never fully
    inflated — we read one byte past the ceiling only to detect overflow."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
        out = f.read(max_out + 1)
        if len(out) > max_out:
            raise DecompressionBomb(f"gzip output exceeds {max_out} bytes")
    return out


def inflate_bounded(data: bytes, *, max_out: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """zlib/DEFLATE-inflate *data* with a hard *max_out* ceiling, in bounded chunks.

    Each ``decompress`` call yields at most ``_CHUNK`` bytes; we drain buffered
    output with empty feeds after the input is consumed, checking the ceiling
    throughout, so nothing larger than the cap is ever accumulated."""
    d = zlib.decompressobj()
    out = bytearray()
    to_feed = data
    while True:
        chunk = d.decompress(to_feed, _CHUNK)
        out += chunk
        if len(out) > max_out:
            raise DecompressionBomb(f"zlib output exceeds {max_out} bytes")
        if d.unconsumed_tail:
            to_feed = d.unconsumed_tail          # input left over (output was capped)
        elif chunk:
            to_feed = b""                        # input consumed; drain buffered output
        else:
            break                                # nothing left to produce
    out += d.flush()
    if len(out) > max_out:
        raise DecompressionBomb(f"zlib output exceeds {max_out} bytes")
    return bytes(out)
