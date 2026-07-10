"""
openvc.proof._jcs — RFC 8785 JSON Canonicalization Scheme (JCS).

A dependency-light, hand-rolled canonicalizer used by the JCS Data Integrity
cryptosuites (``eddsa-jcs-2022`` / ``ecdsa-jcs-2019``) so a whole-document proof
canonicalizes with **no** RDF/`pyld` dependency. `canonicalize(value)` returns the
canonical UTF-8 bytes; the two edge cases hand-rolled JCS gets wrong are handled
explicitly: object member ordering is by the keys' **UTF-16 code units** (not code
points), and numbers use the **ECMAScript** ``Number.prototype.toString`` shortest
form (RFC 8785 §3.2.2.3 / ECMA-262 §6.1.6.1.20).
"""
from __future__ import annotations

from typing import Any

# Recursion bound for _serialize: deep enough for any real credential (which nest a
# handful of levels), shallow enough to raise JcsError with ample C-stack to spare.
_MAX_DEPTH = 100

# JSON short escapes (RFC 8785 §3.2.2.2); other C0 controls -> \u00XX; the rest verbatim.
_SHORT_ESCAPE = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


class JcsError(Exception):
    """A value cannot be JCS-canonicalized (e.g. a non-finite number)."""


def _code_units(s: str) -> tuple[int, ...]:
    """The string's UTF-16 code units — JCS orders object members by these, which
    differs from Python's default code-point order only for non-BMP characters
    (each encoded as a surrogate pair)."""
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:                       # non-BMP -> surrogate pair (two code units)
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    return tuple(units)


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _SHORT_ESCAPE.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)                    # keep as UTF-8 (RFC 8785 keeps non-ASCII raw)
    out.append('"')
    return "".join(out)


def _number(value: Any) -> str:
    """Serialise an int/float per RFC 8785 (ECMAScript number-to-string)."""
    if isinstance(value, bool):               # bool is an int subclass — not a JSON number
        raise JcsError("bool is not a JSON number")
    if isinstance(value, int):
        return str(value)                     # integers are exact
    if isinstance(value, float):
        return _ecmascript_double(value)
    raise JcsError(f"unsupported number type {type(value).__name__}")


def _ecmascript_double(d: float) -> str:
    """ECMA-262 Number::toString for a finite double (RFC 8785 §3.2.2.3)."""
    import math
    if math.isnan(d) or math.isinf(d):
        raise JcsError("NaN / Infinity are not valid JSON numbers")
    if d == 0:
        return "0"                            # both +0 and -0 canonicalize to "0"
    # Python's repr gives the shortest round-tripping decimal (same digits as ECMAScript);
    # reformat into ECMAScript's exponent conventions.
    return _reformat_ecmascript(repr(d))


def _reformat_ecmascript(r: str) -> str:
    """Reformat Python's shortest-repr *r* into ECMAScript's presentation rules.

    Python's ``repr`` already yields the shortest round-tripping *digits* (same
    algorithm ECMAScript uses); only the layout differs (exponent thresholds and
    formatting). We recover the two ECMA-262 §6.1.6.1.20 quantities — ``digits``
    (the significant digits, no leading/trailing zeros) and ``n`` (how many digits
    sit left of the decimal point, relative to the first significant digit) — then
    lay them out.
    """
    neg = r.startswith("-")
    if neg:
        r = r[1:]
    mantissa, _, exp_s = r.partition("e")
    int_part, _, frac_part = mantissa.partition(".")
    combined = int_part + frac_part
    point_pos = len(int_part) + (int(exp_s) if exp_s else 0)   # point offset within `combined`
    first_sig = len(combined) - len(combined.lstrip("0"))      # index of first non-zero digit
    digits = combined.strip("0") or "0"                        # significant digits only
    n = point_pos - first_sig
    s = _assemble_ecmascript(digits, len(digits), n)
    return ("-" + s) if neg else s


def _assemble_ecmascript(digits: str, k: int, n: int) -> str:
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    exp = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return f"{digits}e{exp}"
    return f"{digits[0]}.{digits[1:]}e{exp}"


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of a JSON value."""
    try:
        return _serialize(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        # `json.loads` can produce a lone surrogate (e.g. "\ud800"); it survives the
        # escape pass and only fails at the final UTF-8 encode. Fail closed as JcsError
        # so the module honours its own contract instead of leaking UnicodeEncodeError.
        raise JcsError(f"string contains an unpaired surrogate: {exc}") from exc


def _serialize(value: Any, depth: int = 0) -> str:
    # A hostile deeply-nested document must fail closed as a JcsError long before it
    # exhausts Python's C-stack (RecursionError); no real credential nests this deep.
    if depth > _MAX_DEPTH:
        raise JcsError(f"maximum nesting depth {_MAX_DEPTH} exceeded")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: _code_units(_require_str_key(kv[0])))
        return "{" + ",".join(
            _escape_string(k) + ":" + _serialize(v, depth + 1) for k, v in members) + "}"
    raise JcsError(f"cannot canonicalize a {type(value).__name__}")


def _require_str_key(key: Any) -> str:
    if not isinstance(key, str):
        raise JcsError(f"object keys must be strings, got {type(key).__name__}")
    return key
