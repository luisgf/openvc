"""
openvc._json — the JSON loader for untrusted input, bounded in depth.

CPython 3.14's ``json.loads`` accepts about 116k levels of nesting, far deeper than the
rest of the interpreter tolerates. ``repr()`` of such a value overflows at about 70k,
``==`` between two of them at about 43k, and a Python-level walk (``copy.deepcopy``, a
recursive validator) at about 1000. A value that parses can therefore still raise a
bare ``RecursionError`` wherever openvc formats, compares or walks it. That escapes
``OpenvcError`` and aborts a whole ``verify_many`` batch.

Rather than make every such site safe, openvc refuses the value where it enters.
:func:`loads` raises ``ValueError`` for JSON nested deeper than :data:`MAX_DEPTH`, which
every call site already maps to its typed error. :func:`nesting_exceeds` applies the
same bound to an object a caller hands over already parsed. No credential, DID document,
status list or trust list comes near the bound; the JCS canonicaliser and the SD-JWT
unpacker already stop at the same depth.

A second hostile shape lives in the same place. JSON allows ``"\\ud800"``, an escape for a
lone UTF-16 surrogate, and ``json.loads`` returns a ``str`` holding that code point. Such
a string cannot be encoded to UTF-8, so a bare ``.encode("utf-8")`` on attacker text is a
bare ``UnicodeEncodeError``: not an ``OpenvcError``, and it aborts a whole ``verify_many``
batch the same way. :func:`utf8` is the encode for those sites. It refuses the string with
the caller's own typed error and never repairs it. ``errors="replace"`` would make two
different inputs encode to the same bytes (``"\\ud800"`` and ``"?"`` are both ``b"?"``).
``errors="surrogatepass"`` is lossless but emits bytes that are not UTF-8 (``ED A0 80``
through ``ED BF BF``): a strict decoder rejects them, and a conformant encoder elsewhere
never produces them (a WHATWG ``TextEncoder`` writes U+FFFD for the same code point), so
the hash would not match the one another implementation computes. The loader itself keeps
accepting the escape: a JOSE issuer may sign one, and what verifies is what the issuer
signed.

It imports only the standard library, so any module can use it without an import cycle.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

# The deepest container nesting openvc accepts from untrusted input: [[...]] counts one
# level per array, {"a": {...}} one per object. The same bound as JCS and SD-JWT.
MAX_DEPTH = 100


def nesting_exceeds(value: Any, limit: int = MAX_DEPTH) -> bool:
    """True when *value* nests lists / tuples / mappings deeper than *limit*.

    Iterative, so it never recurses. A self-referencing container built in process
    reads as too deep instead of looping."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, Mapping):
            children: Any = node.values()
        elif isinstance(node, (list, tuple)):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children
                     if isinstance(child, (Mapping, list, tuple)))
    return False


def loads(data: str | bytes | bytearray) -> Any:
    """``json.loads`` for untrusted input.

    Raises ``ValueError`` on malformed JSON (a ``JSONDecodeError`` stays one), on
    nesting too deep for the interpreter to parse, and on nesting deeper than
    :data:`MAX_DEPTH`."""
    try:
        value = json.loads(data)
    except RecursionError as exc:              # deeper than the interpreter can parse
        raise ValueError("JSON is nested too deeply to parse") from exc
    if nesting_exceeds(value):
        # drop the tree first: the traceback keeps this frame alive, so a rejected
        # item would otherwise pin its whole parsed value for as long as the error lives
        del value
        raise ValueError(f"JSON is nested deeper than {MAX_DEPTH} levels")
    return value


def utf8(text: str, *, error: type[Exception], what: str) -> bytes:
    """``text.encode("utf-8")``, refusing a lone UTF-16 surrogate with *error*.

    JSON can carry one (``"\\ud800"``) and ``json.loads`` hands it back as a ``str`` that
    no UTF-8 encoding exists for. *error* is the typed exception of the lane that asks, so
    the failure stays inside its taxonomy instead of escaping as a bare
    ``UnicodeEncodeError``; *what* names the value in the message. The message carries the
    code point and its index, never the text itself (it is attacker-controlled and can be
    arbitrarily long). The string is never repaired."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise error(
            f"{what} holds a lone UTF-16 surrogate "
            f"(U+{ord(text[exc.start]):04X} at index {exc.start})") from exc
