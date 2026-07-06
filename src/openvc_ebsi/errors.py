"""openvc_ebsi.errors — the EBSI-plugin error root.

Sits under openvc's library-wide :class:`~openvc.errors.OpenvcError`, so every EBSI
failure is catchable both as :class:`EbsiError` and as ``OpenvcError``.
"""
from __future__ import annotations

from openvc.errors import OpenvcError


class EbsiError(OpenvcError):
    """Base class for every error the EBSI plugin raises."""
