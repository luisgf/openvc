"""Python versions openvc still runs on after upstream end-of-life — and the warning
an import gets on one of them.

A retired CPython is **deprecated, not removed**: openvc 1.x keeps installing on it,
keeps it in CI, and warns once at import; the next MAJOR raises ``requires-python``
(see ``wiki/Versioning-and-Deprecation.md``, *Supported Python versions*).
"""
from __future__ import annotations

import sys
import warnings
from typing import Any

# (major, minor) -> (upstream end-of-life date, the openvc release that drops it)
_DEPRECATED_PYTHONS: dict[tuple[int, int], tuple[str, str]] = {
    (3, 10): ("2026-10-01", "2.0"),
}


def python_deprecation_message(version_info: tuple[Any, ...] | None = None) -> str | None:
    """The deprecation notice for *version_info* (default: the running interpreter),
    or ``None`` when that Python is fully supported."""
    major, minor = (sys.version_info if version_info is None else version_info)[:2]
    entry = _DEPRECATED_PYTHONS.get((major, minor))
    if entry is None:
        return None
    eol, removal = entry
    return (
        f"openvc: Python {major}.{minor} reached end-of-life on {eol} and is deprecated. "
        f"openvc 1.x still installs and runs on it, but openvc {removal} will require "
        "Python 3.11 or later (https://github.com/luisgf/openvc/issues/74)."
    )


def warn_if_python_deprecated(version_info: tuple[Any, ...] | None = None) -> None:
    """Warn once when openvc is imported on a deprecated Python.

    A ``FutureWarning``, not a ``DeprecationWarning``: one raised while a package is
    being imported is attributed to importlib's frames, and the default filters hide a
    ``DeprecationWarning`` anywhere but ``__main__`` — so outside a test runner nobody
    running a retired interpreter would ever see it. (``skip_file_prefixes``, which
    would fix the attribution, only exists from Python 3.12.)
    """
    message = python_deprecation_message(version_info)
    if message is not None:
        warnings.warn(message, FutureWarning, stacklevel=2)
