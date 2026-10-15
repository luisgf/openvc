"""
openvc.proof.errors — the shared error taxonomy for every proof suite.

``ProofError`` is the family root (``except ProofError`` catches any proof-suite
failure). The leaves below mean the SAME thing across VC-JWT, SD-JWT VC and Data
Integrity, so they are defined ONCE here rather than once per suite — there is a
single ``SignatureInvalid`` that ``except SignatureInvalid`` catches whichever suite
raised it (previously each suite defined its own, so a suite-qualified
``except data_integrity.SignatureInvalid`` silently missed the ecdsa-sd one).

Genuinely suite-specific conditions keep their own error class under this root, in
the suite module: ``SdJwtError`` (openvc.proof.sd_jwt), ``EcdsaSdError`` /
``ProofValueMalformed`` (openvc.proof.ecdsa_sd), ``DataIntegrityError``
(openvc.proof.data_integrity). The post-signature policy failures
(``CredentialExpired``, ``ProofPurposeMismatch`` …) live in
``openvc.proof._verify_common`` and also subclass ``ProofError``.

``KeyResolutionError`` is the one leaf with a second base: it is also the pipeline's
``KeyResolutionFailed`` (:mod:`openvc.errors`), so a key-resolution failure is a
``KeyResolutionFailed`` on every lane, JOSE and Data Integrity alike.
"""
from __future__ import annotations

from ..errors import KeyResolutionFailed, OpenvcError


class ProofError(OpenvcError):
    """Base class for every proof-suite failure (signature, format, temporal, policy)."""


class SignatureInvalid(ProofError):
    """A proof/signature did not verify."""


class ProofMalformed(ProofError):
    """The proof object is structurally invalid — missing or wrongly typed fields."""


class UnsupportedCryptosuite(ProofError):
    """The proof declares a cryptosuite this suite does not implement."""


class UnsupportedAlgorithm(ProofError):
    """The JOSE algorithm is not in the ``{ES256, ES384, EdDSA, Ed25519}`` allow-list."""


class MalformedToken(ProofError):
    """A compact JWS / SD-JWT string is not well-formed."""


class ClaimsInvalid(ProofError):
    """A required claim is missing, malformed, or does not satisfy policy."""


# Post-signature policy failures, shared by every suite's verify() (the checks live
# in openvc.proof._verify_common; the classes live here as the canonical home).
class CredentialExpired(ProofError):
    """The credential's validity window has ended (validUntil / expirationDate / proof expires)."""


class CredentialNotYetValid(ProofError):
    """The credential's validity window has not started (validFrom / issuanceDate)."""


class MalformedTimestamp(ProofError):
    """A validity timestamp is present but not a parseable date-time (fails closed)."""


class ProofPurposeMismatch(ProofError):
    """The proof's proofPurpose is not the expected one (e.g. assertionMethod)."""


class KeyResolutionError(ProofError, KeyResolutionFailed):
    """The proof's verificationMethod key could not be resolved.

    Raised by every Data Integrity lane, sync and async. It is both a :class:`ProofError`
    and the pipeline's :class:`~openvc.errors.KeyResolutionFailed` (hence also a
    :class:`~openvc.errors.VerificationError`), so ``except ProofError``, ``except
    KeyResolutionFailed`` and ``except VerificationError`` each catch it. The JOSE lanes
    raise the plain ``KeyResolutionFailed``, which is not a ``ProofError``, so
    ``except KeyResolutionError`` and ``except ProofError`` still do not catch a JOSE
    failure."""


class PresentationBindingError(ProofError):
    """A presentation proof's challenge / domain does not match what the verifier expects."""


__all__ = [
    "ClaimsInvalid",
    "CredentialExpired",
    "CredentialNotYetValid",
    "KeyResolutionError",
    "MalformedTimestamp",
    "MalformedToken",
    "PresentationBindingError",
    "ProofError",
    "ProofMalformed",
    "ProofPurposeMismatch",
    "SignatureInvalid",
    "UnsupportedAlgorithm",
    "UnsupportedCryptosuite",
]
