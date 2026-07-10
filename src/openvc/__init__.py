"""openvc — generic Verifiable Credentials core."""

# Single source of truth for the version (pyproject reads it by AST — keep it a
# plain string literal). The /release skill bumps this line.
__version__ = "1.20.0"

# The one-call verification pipeline is the headline API (see openvc.verify); the
# signing backends (Ed25519 / P256 / P384), the SigningKey protocol and the
# KeyAgreementKey backend used for HAIP decryption are its signing/key counterpart,
# alongside the signing_key_from_jwk factory and the dependency-light
# verify_signature helper. Everything else is imported from its module (see
# docs/CONVENTIONS.md).
from .errors import OpenvcError  # noqa: E402
from .keys import (  # noqa: E402
    Ed25519SigningKey,
    KeyAgreementKey,
    MLDSASigningKey,
    P256KeyAgreementKey,
    P256SigningKey,
    P384SigningKey,
    mldsa_available,
    signing_key_from_jwk,
    verify_signature,
)
from .proof.vc_jwt import SigningKey  # noqa: E402
from .verify import (  # noqa: E402
    BatchResult,
    VerificationError,
    VerificationPolicy,
    VerificationResult,
    verify_credential,
    verify_many,
)
from .aio import verify_credential_async, verify_many_async  # noqa: E402
from .openid4vp import verify_encrypted_vp_response, verify_vp_token  # noqa: E402

__all__ = [
    "__version__",
    "OpenvcError",
    "verify_credential",
    "verify_many",
    "verify_credential_async",
    "verify_many_async",
    "verify_vp_token",
    "verify_encrypted_vp_response",
    "VerificationPolicy",
    "VerificationResult",
    "BatchResult",
    "VerificationError",
    "Ed25519SigningKey",
    "MLDSASigningKey",
    "P256SigningKey",
    "P384SigningKey",
    "SigningKey",
    "mldsa_available",
    "KeyAgreementKey",
    "P256KeyAgreementKey",
    "signing_key_from_jwk",
    "verify_signature",
]
