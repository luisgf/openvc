"""
openvc.cbor — a bounded, dependency-free CBOR codec (RFC 8949) for the COSE/mdoc
profile.

This is **not** a general CBOR library. It is the small, spec-scoped subset openvc
needs to verify received artifacts — the ISO 18013-5 ``mso_mdoc`` (COSE_Sign1 /
COSE_Mac0, the MSO, ``valueDigests``) and, historically, the ``ecdsa-sd-2023``
proof value. It is hand-rolled on purpose: the project stays dependency-light, and
an unmaintained parser of attacker-controlled bytes is exactly what a fail-closed
verifier must not import (see ADR-0005).

What it supports — RFC 8949 major types, **definite length only**:

* 0/1 — unsigned and **negative** integers (COSE ``alg`` = ``-7``; ``COSE_Key`` labels);
* 2/3 — byte and (UTF-8) text strings;
* 4/5 — arrays and maps (keys must be int / bytes / text — hashable);
* 6 — **tags**, kept as :class:`CborTag` (COSE_Sign1 ``18``, COSE_Mac0 ``17``,
  embedded-CBOR ``24``, date-time ``0``, full-date ``1004``);
* 7 — the simple values ``false`` / ``true`` / ``null``.

Two deliberate properties make it safe for a verifier:

* **Deterministic encoding (RFC 8949 §4.2.1 "core deterministic").** Integers use the
  shortest form; map keys are sorted by their *encoded bytes*. So a structure a
  verifier reconstructs (a COSE ``Sig_structure``, a ``SessionTranscript``) encodes to
  the exact bytes the signer produced.
* **Bytes-as-received.** :func:`decode` records, on every :class:`CborTag`, the *exact*
  encoded bytes of the tagged item (``.raw``). A verifier hashes / verifies over those
  bytes rather than a re-encoding, so a non-canonically-encoded (but validly signed)
  issuer artifact still verifies — you never recompute a digest over bytes the issuer
  did not sign.

Everything fails closed: any malformed input raises :class:`CborError` (an
:class:`~openvc.errors.OpenvcError`), never a bare exception, and nesting is bounded so
a hostile deeply-nested payload cannot exhaust the stack. Indefinite-length items,
floats, and the ``undefined`` simple value are rejected — none appear in the profile.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import OpenvcError

__all__ = [
    "CborError",
    "CborTag",
    "CborRaw",
    "TAG_DATE_TIME",
    "TAG_COSE_MAC0",
    "TAG_COSE_SIGN1",
    "TAG_ENCODED_CBOR",
    "TAG_FULL_DATE",
    "encode",
    "decode",
]

# Tag numbers in the COSE/mdoc profile (RFC 9052 §2, RFC 8949 §3.4, RFC 8943).
TAG_DATE_TIME = 0          # tstr RFC 3339 date-time
TAG_COSE_MAC0 = 17         # COSE_Mac0 (DeviceMac)
TAG_COSE_SIGN1 = 18        # COSE_Sign1 (IssuerAuth / DeviceSignature)
TAG_ENCODED_CBOR = 24      # embedded CBOR: bstr .cbor X  (#6.24)
TAG_FULL_DATE = 1004       # full-date string (RFC 8943)

# Bound the decode recursion so a hostile nested payload fails closed with a typed
# CborError instead of a RecursionError. The profile's deepest real structure — a
# SessionTranscript inside a DeviceAuthentication inside an embedded-CBOR tag — is only
# a handful of levels; 64 is generous headroom without risking the interpreter stack.
_MAX_DEPTH = 64


class CborError(OpenvcError):
    """The bytes are not valid CBOR in the supported profile (fails closed)."""


@dataclass(frozen=True)
class CborRaw:
    """Pre-encoded CBOR bytes to embed **verbatim** when encoding. :func:`encode` emits
    ``.raw`` unchanged, so a signed sub-structure (a ``SessionTranscript``, a
    ``DeviceNameSpacesBytes``) goes into a larger structure as the exact bytes that were
    signed — never a re-encoding that could differ. It is never produced by :func:`decode`."""
    raw: bytes


@dataclass(frozen=True)
class CborTag:
    """A CBOR tagged item (major type 6): a *tag* number wrapping a *value*.

    ``raw`` is the exact encoded bytes of the whole tagged item as it was decoded —
    set by :func:`decode`, ``None`` when you construct a tag to encode. It lets a
    verifier hash or signature-check the item *as received* (e.g. an
    ``IssuerSignedItemBytes`` or a ``MobileSecurityObjectBytes``) rather than a
    re-encoding, which could differ if the issuer did not encode canonically. ``raw``
    is excluded from equality/hash so two tags with the same ``(tag, value)`` compare
    equal regardless of provenance.
    """
    tag: int
    value: Any
    raw: bytes | None = field(default=None, compare=False, hash=False)


# --------------------------------------------------------------------------- #
# encode — deterministic (RFC 8949 §4.2.1 core deterministic)
# --------------------------------------------------------------------------- #

def _head(major: int, n: int, out: bytearray) -> None:
    mt = major << 5
    if n < 24:
        out.append(mt | n)
    elif n < 0x100:
        out += bytes((mt | 24, n))
    elif n < 0x10000:
        out += bytes((mt | 25,)) + n.to_bytes(2, "big")
    elif n < 0x100000000:
        out += bytes((mt | 26,)) + n.to_bytes(4, "big")
    elif n < 0x10000000000000000:
        out += bytes((mt | 27,)) + n.to_bytes(8, "big")
    else:
        raise CborError("integer out of range for 64-bit CBOR")


def _encode(obj: Any, out: bytearray) -> None:
    # bool is a subclass of int — test it first, map to the simple values.
    if obj is None:
        out.append(0xF6)
    elif obj is True:
        out.append(0xF5)
    elif obj is False:
        out.append(0xF4)
    elif isinstance(obj, CborRaw):
        out += obj.raw
    elif isinstance(obj, CborTag):
        _head(6, obj.tag, out)
        _encode(obj.value, out)
    elif isinstance(obj, int):
        if obj < 0:
            _head(1, -1 - obj, out)          # major 1 encodes -1-n
        else:
            _head(0, obj, out)
    elif isinstance(obj, (bytes, bytearray)):
        _head(2, len(obj), out)
        out += bytes(obj)
    elif isinstance(obj, str):
        raw = obj.encode("utf-8")
        _head(3, len(raw), out)
        out += raw
    elif isinstance(obj, (list, tuple)):
        _head(4, len(obj), out)
        for item in obj:
            _encode(item, out)
    elif isinstance(obj, dict):
        # Core-deterministic map ordering: sort by the ENCODED key bytes (not the
        # Python value), so e.g. int and text keys order the way RFC 8949 requires.
        encoded = sorted((encode(k), v) for k, v in obj.items())
        _head(5, len(encoded), out)
        for ek, v in encoded:
            out += ek
            _encode(v, out)
    else:
        raise CborError(f"cannot encode type {type(obj).__name__} as CBOR")


def encode(obj: Any) -> bytes:
    """Encode *obj* as deterministic CBOR (RFC 8949 §4.2.1). Accepts ``int``, ``bytes``,
    ``str``, ``bool``, ``None``, ``list``/``tuple``, ``dict`` (int/bytes/text keys) and
    :class:`CborTag`. Raises :class:`CborError` on an unsupported type or an out-of-range
    integer."""
    out = bytearray()
    _encode(obj, out)
    return bytes(out)


# --------------------------------------------------------------------------- #
# decode — fail-closed, definite-length only, records tag raw bytes
# --------------------------------------------------------------------------- #

def _read_head(data: bytes, i: int) -> tuple[int, int, int]:
    if i >= len(data):
        raise CborError("CBOR: truncated (expected an item head)")
    ib = data[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        return major, info, i
    if info == 31:
        raise CborError("CBOR: indefinite-length items are not supported")
    nbytes = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if nbytes is None:                                   # 28/29/30 are reserved
        raise CborError("CBOR: reserved additional-information value")
    if i + nbytes > len(data):
        raise CborError("CBOR: truncated integer/length")
    return major, int.from_bytes(data[i:i + nbytes], "big"), i + nbytes


def _decode_at(data: bytes, i: int, depth: int) -> tuple[Any, int]:
    if depth > _MAX_DEPTH:
        raise CborError("CBOR: maximum nesting depth exceeded")
    start = i
    major, n, i = _read_head(data, i)
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        if i + n > len(data):
            raise CborError("CBOR: truncated byte string")
        return data[i:i + n], i + n
    if major == 3:
        if i + n > len(data):
            raise CborError("CBOR: truncated text string")
        try:
            return data[i:i + n].decode("utf-8"), i + n
        except UnicodeDecodeError as exc:                # attacker bytes -> fail closed
            raise CborError(f"CBOR: text string is not valid UTF-8: {exc}") from exc
    if major == 4:
        out_list = []
        for _ in range(n):
            item, i = _decode_at(data, i, depth + 1)
            out_list.append(item)
        return out_list, i
    if major == 5:
        out_map: dict[Any, Any] = {}
        for _ in range(n):
            key, i = _decode_at(data, i, depth + 1)
            val, i = _decode_at(data, i, depth + 1)
            if not isinstance(key, (int, bytes, str)) or isinstance(key, bool):
                # a list/map/tag/bool key is unhashable or out of profile -> fail closed
                raise CborError("CBOR: map key must be an integer, byte, or text string")
            if key in out_map:
                # RFC 8949 §5.6 / COSE + ISO 18013-5 deterministic encoding: a decoder of
                # attacker bytes must reject duplicate keys, not silently keep the last.
                raise CborError(f"CBOR: duplicate map key {key!r}")
            out_map[key] = val
        return out_map, i
    if major == 6:
        value, i = _decode_at(data, i, depth + 1)
        return CborTag(n, value, raw=data[start:i]), i
    # major == 7: accept ONLY the canonical single-byte simple values false / true / null
    # (additional-info 20 / 21 / 22). Floats (25/26/27), the 1-byte simple form (24), and
    # 'undefined' (23) are rejected — gate on the info byte, NOT the decoded argument, so a
    # float whose argument bytes happen to equal 20/21/22 cannot masquerade as a simple value.
    info = data[start] & 0x1F
    if info == 20:
        return False, i
    if info == 21:
        return True, i
    if info == 22:
        return None, i
    raise CborError(f"CBOR: unsupported simple/float value (additional-info {info})")


def decode(data: bytes) -> Any:
    """Decode a single top-level CBOR item from *data*. Trailing bytes after the item,
    indefinite-length items, floats, and any structural error raise :class:`CborError`
    (never a bare exception). Tagged items decode to :class:`CborTag` with ``.raw`` set
    to the item's exact encoded bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CborError("CBOR: decode expects bytes")
    data = bytes(data)
    obj, i = _decode_at(data, 0, 0)
    if i != len(data):
        raise CborError("CBOR: trailing bytes after the top-level item")
    return obj


def decode_from(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Like :func:`decode` but decode one item starting at *offset* and return
    ``(item, next_offset)`` — for a caller that walks several concatenated items (e.g.
    the content of an embedded-CBOR ``bstr``). Does not require *data* to be fully
    consumed."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CborError("CBOR: decode expects bytes")
    return _decode_at(bytes(data), offset, 0)
