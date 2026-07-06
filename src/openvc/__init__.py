"""openvc — generic Verifiable Credentials core."""

# Single source of truth for the version (pyproject reads it by AST — keep it a
# plain string literal). The /release skill bumps this line.
__version__ = "0.8.1"

# The one-call verification pipeline is the headline API (see openvc.verify).
from .errors import OpenvcError  # noqa: E402
from .verify import (  # noqa: E402
    VerificationError,
    VerificationPolicy,
    VerificationResult,
    verify_credential,
)

__all__ = [
    "__version__",
    "OpenvcError",
    "verify_credential",
    "VerificationPolicy",
    "VerificationResult",
    "VerificationError",
]
