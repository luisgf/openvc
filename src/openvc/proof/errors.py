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
"""
from __future__ import annotations

from ..errors import OpenvcError


class ProofError(OpenvcError):
    """Base class for every proof-suite failure (signature, format, temporal, policy)."""


class SignatureInvalid(ProofError):
    """A proof/signature did not verify."""


class ProofMalformed(ProofError):
    """The proof object is structurally invalid — missing or wrongly typed fields."""


class UnsupportedCryptosuite(ProofError):
    """The proof declares a cryptosuite this suite does not implement."""


class UnsupportedAlgorithm(ProofError):
    """The JOSE algorithm is not in the ``{ES256, EdDSA}`` allow-list."""


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


class KeyResolutionError(ProofError):
    """The proof's verificationMethod key could not be resolved."""


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
