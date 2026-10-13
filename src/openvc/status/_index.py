"""
openvc.status._index — the one rule for a status-list index read off a credential.

Both status conventions carry the index as issuer-signed but attacker-shaped JSON:
the W3C ``credentialStatus.statusListIndex`` (a base-10 string, per the Bitstring
Status List REC) and the IETF ``status.status_list.idx`` (a JSON integer, per
draft-ietf-oauth-status-list). Reading either with ``int()`` has traps that each
parser used to meet on its own:

* ``int(float("inf"))`` raises a bare ``OverflowError``. ``json.loads`` yields that
  float for ``Infinity`` and for an overflowing literal such as ``1e400``, so the
  exception escaped ``OpenvcError`` and aborted a whole ``verify_many`` batch.
* ``int(True)`` is ``1`` and ``int(3.7)`` is ``3``: a bool or a fraction was read
  as some other credential's bit instead of being refused.
* ``int(" 5")``, ``int("+5")``, ``int("5_0")`` and ``int("\\u0665")`` all succeed,
  so a string no other verifier reads as an index pointed at a bit here.
* An integer far past any list's end (``1`` and 400 zeros) addresses nothing.

:func:`status_index` accepts a non-negative ``int`` (never a ``bool``) and, where
the convention allows it, a string of ASCII digits — and nothing else. It caps the
value at :data:`MAX_STATUS_INDEX`. Everything else is a typed
:class:`~openvc.status.bitstring.StatusListError`.
"""
from __future__ import annotations

from typing import Any

from ._decompress import MAX_DECOMPRESSED_BYTES
from .bitstring import StatusListError

# No list openvc decodes holds more statuses than this: the decompression ceiling at
# the densest packing (one bit per status, both conventions). An index at or past it
# addresses nothing, whatever list it names.
MAX_STATUS_INDEX = MAX_DECOMPRESSED_BYTES * 8

_MAX_DIGITS = len(str(MAX_STATUS_INDEX))


def brief(value: Any) -> str:
    """A short, safe rendering of a hostile status value for an error message. Never calls
    ``repr()`` on a container (deep nesting overflows it) or on a huge int (past
    ``sys.get_int_max_str_digits`` it raises a bare ``ValueError``)."""
    if isinstance(value, str):
        return repr(value[:32]) + ("..." if len(value) > 32 else "")
    if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 64:
        return f"a {value.bit_length()}-bit integer"
    if isinstance(value, (bool, int, float)):
        return repr(value)
    return f"a {type(value).__name__}"


def status_index(value: Any, *, field: str, allow_string: bool) -> int:
    """Return *value* as a status-list index, or raise :class:`StatusListError`.

    A non-negative ``int`` below :data:`MAX_STATUS_INDEX` is accepted; a ``bool`` is
    not, nor is any ``float`` (``NaN``, ``±Infinity``, ``1e400``, ``3.7``, ``5.0``).
    With *allow_string*, a non-empty string of ASCII digits is accepted too, leading
    zeros included; a sign, whitespace, an underscore or a non-ASCII digit is not.
    *field* names the claim in the error."""
    if isinstance(value, str) and allow_string:
        if not (value.isascii() and value.isdigit()):
            raise StatusListError(
                f"{field} must be a base-10 string of ASCII digits, got {brief(value)}")
        digits = value.lstrip("0") or "0"
        if len(digits) > _MAX_DIGITS:          # bound the length before int() parses it
            raise StatusListError(
                f"{field} {brief(value)} is past the largest list openvc decodes "
                f"({MAX_STATUS_INDEX} statuses)")
        value = int(digits)
    elif not isinstance(value, int) or isinstance(value, bool):
        kind = "an integer or a base-10 string" if allow_string else "an integer"
        raise StatusListError(f"{field} must be {kind}, got {brief(value)}")
    if value < 0:
        raise StatusListError(f"{field} must be non-negative, got {brief(value)}")
    if value >= MAX_STATUS_INDEX:
        raise StatusListError(
            f"{field} {brief(value)} is past the largest list openvc decodes "
            f"({MAX_STATUS_INDEX} statuses)")
    return value
