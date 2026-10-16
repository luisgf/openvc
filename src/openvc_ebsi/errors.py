"""openvc_ebsi.errors — the EBSI-plugin error root.

Sits under openvc's library-wide :class:`~openvc.errors.OpenvcError`, so every EBSI
failure is catchable both as :class:`EbsiError` and as ``OpenvcError``.
"""
from __future__ import annotations

from openvc.errors import OpenvcError


class EbsiError(OpenvcError):
    """Base class for every error the EBSI plugin raises."""


class MalformedRegistryResponse(EbsiError):
    """A registry returned a 200 body that is not the JSON object the adapter needs
    (a ``null`` / array / string / number body, e.g. from a flaky or compromised
    registry). Fails closed as a typed :class:`EbsiError` rather than leaking a bare
    ``AttributeError`` past the error family callers catch."""


class UnknownEbsiEnvironment(EbsiError, ValueError):
    """``for_ebsi`` was given an environment name the table does not hold: an unknown or
    wrong-case string, an empty one, or a value that is not a ``str`` at all (``None``, a
    number, an unhashable ``list``).

    It is also a :class:`ValueError`, which is what ``for_ebsi`` raised for an unknown name
    before this class existed, so ``except ValueError`` keeps working. Code that compares the
    exact class (``type(exc) is ValueError``) must compare this one."""
