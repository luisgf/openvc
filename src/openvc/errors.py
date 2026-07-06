"""
openvc.errors — the library-wide root exception.

Every error ``openvc`` (and the ``openvc_ebsi`` plugin) raises descends from
:class:`OpenvcError`, so a caller can catch *any* openvc failure with a single
``except OpenvcError``. The per-area roots (``ProofError``, ``DidError``,
``StatusListError``, ``VerificationError``, ``EbsiError`` …) still exist and are
still catchable individually — this only inserts a common base above them.

It imports nothing, so every module can subclass it without an import cycle.
"""
from __future__ import annotations


class OpenvcError(Exception):
    """Base class for every exception raised by openvc and its plugins."""


__all__ = [
    "OpenvcError",
]
