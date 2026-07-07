"""openvc — generic Verifiable Credentials core."""

# Single source of truth for the version (pyproject reads it by AST — keep it a
# plain string literal). The /release skill bumps this line.
__version__ = "1.5.0"

# The one-call verification pipeline is the headline API (see openvc.verify); the
# two signing backends and the SigningKey protocol are the signing counterpart.
# Everything else is imported from its module (see docs/CONVENTIONS.md).
from .errors import OpenvcError  # noqa: E402
from .keys import Ed25519SigningKey, P256SigningKey  # noqa: E402
from .proof.vc_jwt import SigningKey  # noqa: E402
from .verify import (  # noqa: E402
    VerificationError,
    VerificationPolicy,
    VerificationResult,
    verify_credential,
)
from .openid4vp import verify_encrypted_vp_response, verify_vp_token  # noqa: E402

__all__ = [
    "__version__",
    "OpenvcError",
    "verify_credential",
    "verify_vp_token",
    "verify_encrypted_vp_response",
    "VerificationPolicy",
    "VerificationResult",
    "VerificationError",
    "Ed25519SigningKey",
    "P256SigningKey",
    "SigningKey",
]
