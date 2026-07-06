"""openvc — generic Verifiable Credentials core."""

# Single source of truth for the version (pyproject reads it by AST — keep it a
# plain string literal). The /release skill bumps this line.
__version__ = "0.5.0"

# The one-call verification pipeline is the headline API (see openvc.verify).
from .verify import (  # noqa: E402
    VerificationError,
    VerificationPolicy,
    VerificationResult,
    verify_credential,
)

__all__ = [
    "__version__",
    "verify_credential",
    "VerificationPolicy",
    "VerificationResult",
    "VerificationError",
]
