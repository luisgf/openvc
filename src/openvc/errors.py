"""
openvc.errors — the library-wide root exception.

Every error ``openvc`` (and the ``openvc_ebsi`` plugin) raises descends from
:class:`OpenvcError`, so a caller can catch *any* openvc failure with a single
``except OpenvcError``. The per-area roots (``ProofError``, ``DidError``,
``StatusListError``, ``VerificationError``, ``EbsiError`` …) still exist and are
still catchable individually — this only inserts a common base above them.

It imports nothing, so every module can subclass it without an import cycle.

Two pipeline classes are defined here rather than in :mod:`openvc.verify` for the same
reason: :class:`~openvc.proof.errors.KeyResolutionError`, a proof-suite error, is also a
:class:`KeyResolutionFailed`, and ``openvc.proof`` cannot import ``openvc.verify`` (the
pipeline imports the proofs). They are re-exported from :mod:`openvc.verify` and keep
``openvc.verify`` as their ``__module__``, so ``from openvc.verify import
VerificationError`` and a traceback line ``openvc.verify.KeyResolutionFailed: …`` are
exactly what they were.
"""
from __future__ import annotations


class OpenvcError(Exception):
    """Base class for every exception raised by openvc and its plugins."""


class VerificationError(OpenvcError):
    """A pipeline-level failure (not a proof-signature failure)."""

    # defined here so openvc.proof can subclass it, but still reported as the
    # openvc.verify class it was before: tracebacks, repr and pickle are unchanged
    __module__ = "openvc.verify"


class KeyResolutionFailed(VerificationError):
    """The issuer's (or holder's) key could not be resolved: the DID or its document
    could not be fetched or parsed, the DID method has no resolver, or the document does
    not hold the key the credential names.

    Every verification lane raises this class or a subclass of it. The Data Integrity
    lanes raise the subclass :class:`~openvc.proof.errors.KeyResolutionError`, which is
    also a :class:`~openvc.proof.errors.ProofError`."""

    __module__ = "openvc.verify"


__all__ = [
    "KeyResolutionFailed",
    "OpenvcError",
    "VerificationError",
]
