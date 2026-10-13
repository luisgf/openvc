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

It imports only the standard library, so any module can use it without an import cycle.
"""
from __future__ import annotations

import json
from typing import Any

# The deepest container nesting openvc accepts from untrusted input: [[...]] counts one
# level per array, {"a": {...}} one per object. The same bound as JCS and SD-JWT.
MAX_DEPTH = 100


def nesting_exceeds(value: Any, limit: int = MAX_DEPTH) -> bool:
    """True when *value* nests lists / tuples / dicts deeper than *limit*.

    Iterative, so it never recurses. A self-referencing container built in process
    reads as too deep instead of looping."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, (list, tuple)):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children
                     if isinstance(child, (dict, list, tuple)))
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
        raise ValueError(f"JSON is nested deeper than {MAX_DEPTH} levels")
    return value
