"""
openvc.status._index — the one rule for a status-list index and a status-list size.

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

The rule is not only the verifier's. The issuer-side builders (``issue.py``) and the
codec (``bitstring.py``, ``token_status_list.py``) call it too, so openvc never mints a
pointer or a list that its own verifier refuses: :func:`status_index` for an index,
:func:`packed_length` for the size of a list, :func:`locate_status` for a read or write
against a list already in memory.
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
        value = plain_str(value)       # a subclass's __getitem__ / __len__ may raise or lie
        return repr(value[:32]) + ("..." if len(value) > 32 else "")
    if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 64:
        return f"a {value.bit_length()}-bit integer"
    if isinstance(value, (bool, int, float)):
        return repr(value)
    return f"a {type(value).__name__}"


def plain_str(value: str) -> str:
    """*value* as an exact built-in ``str``, holding the characters it holds, whatever the
    ``str`` subclass it came in says about itself.

    The ``str`` counterpart of :func:`plain_int`. A subclass can override ``__len__``,
    ``__bool__``, ``__getitem__``, ``__eq__``, ``__hash__``, ``__str__``, ``__format__``
    and ``__repr__``, so a value checked for emptiness, for membership in a set or by
    slicing could be a different one from the string a JSON encoder writes (which reads
    the characters, not the methods). ``str.__str__`` is not a lookup on ``type(value)``:
    it is the C function behind ``str``, which copies a subclass instance into a plain
    ``str``. ``str(value)`` is not the same: it calls the subclass's own ``__str__``.
    Callers check the type first. Every check and every use after it works on the returned
    value, never on the original."""
    return str.__str__(value)


def plain_int(value: int) -> int:
    """*value* as an exact built-in ``int``, equal to the integer it holds, whatever the
    ``int`` subclass it came in says about itself.

    A subclass can override ``__int__``, ``__index__``, ``__str__``, ``__format__``,
    ``__repr__`` and the comparison and arithmetic operators, so a value checked as one
    number could be emitted, compared or measured as another. ``int.__index__`` is not a
    lookup on ``type(value)``: it is the C function behind ``int``, which copies a
    subclass instance into a plain ``int`` and ignores everything the subclass defines.
    ``int(value)`` is not the same: it calls the subclass's own ``__int__``. Callers
    check the type first (a ``bool`` is refused before this). Every check and every use
    after it works on the returned value, never on the original."""
    return int.__index__(value)


def status_index(
    value: Any, *, field: str, allow_string: bool, capped: bool = True
) -> int:
    """Return *value* as a status-list index (an exact ``int``, even from an ``int``
    subclass: :func:`plain_int`), or raise :class:`StatusListError`.

    A non-negative ``int`` below :data:`MAX_STATUS_INDEX` is accepted; a ``bool`` is
    not, nor is any ``float`` (``NaN``, ``±Infinity``, ``1e400``, ``3.7``, ``5.0``).
    With *allow_string*, a non-empty string of ASCII digits is accepted too, leading
    zeros included; a sign, whitespace, an underscore or a non-ASCII digit is not.
    *field* names the claim in the error. ``capped=False`` skips the
    :data:`MAX_STATUS_INDEX` ceiling, for an index into a list already in memory, which
    its own length bounds (:func:`locate_status`); never for an index read off a
    credential."""
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
    else:
        # Before any comparison, and the one value everything below checks and returns:
        # an ``int`` subclass could otherwise pass the checks as 5 and be emitted as -1
        # (``__int__``), as ``'E.FIVE'`` (``__str__``, an ``IntEnum`` before Python 3.11)
        # or lie to ``<`` and ``>=`` itself. (The string branch already made an exact int.)
        value = plain_int(value)
    if value < 0:
        raise StatusListError(f"{field} must be non-negative, got {brief(value)}")
    if capped and value >= MAX_STATUS_INDEX:
        raise StatusListError(
            f"{field} {brief(value)} is past the largest list openvc decodes "
            f"({MAX_STATUS_INDEX} statuses)")
    return value


def packed_length(size: Any, *, per_byte: int, field: str = "size") -> int:
    """The byte length of a list that holds *size* statuses, *per_byte* to a byte, or
    raise :class:`StatusListError`.

    *size* is a non-negative ``int`` (never a ``bool``), and the packed list may not
    exceed :data:`~openvc.status._decompress.MAX_DECOMPRESSED_BYTES`: the verifier
    would refuse to inflate a larger one, so no builder allocates it. At one bit per
    status that is :data:`MAX_STATUS_INDEX` statuses; an 8-bit IETF list holds one
    eighth as many."""
    if not isinstance(size, int) or isinstance(size, bool):
        raise StatusListError(f"{field} must be an integer, got {brief(size)}")
    size = plain_int(size)
    if size < 0:
        raise StatusListError(f"{field} must be non-negative, got {brief(size)}")
    length = (size + per_byte - 1) // per_byte
    if length > MAX_DECOMPRESSED_BYTES:
        raise StatusListError(
            f"{field} {brief(size)} needs a list past the largest openvc decodes "
            f"({MAX_DECOMPRESSED_BYTES} bytes, {MAX_DECOMPRESSED_BYTES * per_byte} statuses)")
    return length


def locate_status(
    index: Any, *, per_byte: int, length: int, unit: str
) -> tuple[int, int]:
    """Where *index* sits in a list of *length* bytes packed *per_byte* statuses to a
    byte: ``(byte_index, position_within_byte)``, or raise :class:`StatusListError`.

    The index is held to the rule of :func:`status_index` (an ``int``, never a ``bool``
    or ``float``) minus the ceiling, which the list's own length replaces. *unit* names
    what a slot is in the error (``bit`` or ``status``)."""
    index = status_index(index, field="status index", allow_string=False, capped=False)
    byte_index, position = divmod(index, per_byte)
    if byte_index >= length:
        raise StatusListError(
            f"status index {brief(index)} out of range for a "
            f"{length * per_byte}-{unit} list")
    return byte_index, position
