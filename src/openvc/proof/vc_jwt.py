"""
openvc.proof.vc_jwt — VC-JWT proof suite (ES256 / EdDSA).

Responsibilities
----------------
* peek_issuer  : read `iss` + `kid` from a token WITHOUT verifying — so the caller
                 knows which DID/key to resolve. The result is UNTRUSTED.
* verify       : verify the JWS signature against a resolved public JWK, validate
                 temporal claims, and reconcile the JWT envelope with the embedded
                 `vc` object per the W3C VC-JWT rules. Returns the credential.
* sign         : assemble a compact JWS by delegating the raw signature to a
                 SigningKey backend (which may be backed by an HSM / Vault), so a
                 private key never has to live in this process.

Security posture
----------------
* Algorithm allow-list is fixed (ES256, ES384, EdDSA). `alg: none`, RS*, HS* are
  rejected before any crypto runs — this is the primary defence against alg-confusion.
  (ES384 is the P-384 leg of the Data Integrity ecdsa-*-2019 suites; it does not change
  the EBSI/EUDI-preferred ES256 path.)
* The verification algorithm is taken from the token header ONLY after checking it
  against the allow-list, and is then pinned when calling the verifier.
* peek_issuer never influences verification; it exists solely to select a key.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import jwt as pyjwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm

# The proof error taxonomy lives in openvc.proof.errors; these are re-exported for
# back-compat (old imports like `from openvc.proof.vc_jwt import SignatureInvalid`).
from .errors import (  # noqa: F401
    ClaimsInvalid,
    MalformedToken,
    ProofError,
    SignatureInvalid,
    UnsupportedAlgorithm,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

ALLOWED_ALGS: frozenset[str] = frozenset({"ES256", "ES384", "EdDSA"})
DEFAULT_LEEWAY_S = 60  # tolerance for clock skew on exp/nbf/iat


# --------------------------------------------------------------------------- #
# Key backend interface (implemented by openvc.keys.{ed25519,p256})
# --------------------------------------------------------------------------- #

@runtime_checkable
class SigningKey(Protocol):
    """A private-key handle. `sign` may call out to an HSM/Vault.

    `sign` MUST return a JWS-compatible signature:
      * ES256  -> raw R||S concatenation, 64 bytes (NOT DER)
      * ES384  -> raw R||S concatenation, 96 bytes (NOT DER)
      * EdDSA  -> raw 64-byte Ed25519 signature
    """
    @property
    def alg(self) -> str:
        """The JOSE algorithm identifier — ``"ES256"``, ``"ES384"`` or ``"EdDSA"``."""
    @property
    def kid(self) -> str:
        """The verification-method id this key signs as (e.g. ``did:…#key-1``)."""
    def sign(self, signing_input: bytes) -> bytes:
        """Sign *signing_input*; return the raw JWS signature (R‖S / 64-byte, never DER)."""


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedCredential:
    credential: dict[str, Any]     # the `vc` object (VCDM)
    issuer: str                    # reconciled issuer DID
    subject: str | None            # credentialSubject.id, if present
    claims: dict[str, Any]         # full JWT claim set (iss, exp, jti, ...)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _split(token: str) -> tuple[str, str, str]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise MalformedToken("token is not a compact JWS (need 3 segments)") from exc
    return header_b64, payload_b64, sig_b64


# --------------------------------------------------------------------------- #
# Proof suite
# --------------------------------------------------------------------------- #

class VcJwtProofSuite:
    """VC-JWT (JOSE-secured Verifiable Credential) proof suite."""

    def __init__(self, *, leeway_s: int = DEFAULT_LEEWAY_S) -> None:
        self._leeway = leeway_s

    # -- untrusted inspection --------------------------------------------- #

    def peek_issuer(self, token: str) -> tuple[str, str | None]:
        """Return (iss, kid) WITHOUT verifying the signature.

        UNTRUSTED. Use only to decide which DID to resolve and which key to fetch.
        Never make a trust decision on this output.
        """
        header_b64, payload_b64, _ = _split(token)
        try:
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            raise MalformedToken("header/payload is not valid base64url JSON") from exc

        iss = payload.get("iss") or (payload.get("vc", {}) or {}).get("issuer")
        if isinstance(iss, dict):          # issuer can be an object {"id": ...}
            iss = iss.get("id")
        if not iss:
            raise MalformedToken("no issuer (iss / vc.issuer) present")
        return iss, header.get("kid")

    def peek_claims(self, token: str) -> dict[str, Any]:
        """Decode the full claim set WITHOUT verifying the signature. UNTRUSTED.
        Used to read TIR accreditation bodies before the trust-chain walk."""
        _, payload_b64, _ = _split(token)
        try:
            return json.loads(_b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            raise MalformedToken("payload is not valid base64url JSON") from exc

    # -- verification ------------------------------------------------------ #

    def verify(
        self,
        token: str,
        *,
        public_key_jwk: dict[str, Any],
        expected_types: list[str] | None = None,
        audience: str | None = None,
    ) -> VerifiedCredential:
        """Verify signature + temporal claims + VC-JWT reconciliation."""
        header_b64, _, _ = _split(token)
        try:
            header = json.loads(_b64url_decode(header_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            raise MalformedToken("invalid JWS header") from exc

        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:                       # allow-list BEFORE crypto
            raise UnsupportedAlgorithm(f"algorithm {alg!r} is not permitted")

        key = self._jwk_to_key(public_key_jwk, alg)

        try:
            claims = pyjwt.decode(
                token,
                key=key,
                algorithms=[alg],                         # pinned, single alg
                leeway=self._leeway,
                audience=audience,
                options={
                    "require": ["iss"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_aud": audience is not None,
                },
            )
        except pyjwt.InvalidSignatureError as exc:
            raise SignatureInvalid(str(exc)) from exc
        except pyjwt.PyJWTError as exc:
            raise ClaimsInvalid(str(exc)) from exc

        credential = claims.get("vc")
        if not isinstance(credential, dict):
            raise ClaimsInvalid("no embedded `vc` object in token")

        issuer, subject = self._reconcile(claims, credential)
        if expected_types:
            self._check_types(credential, expected_types)

        return VerifiedCredential(
            credential=credential, issuer=issuer, subject=subject, claims=claims,
        )

    # -- signing (issuance) ----------------------------------------------- #

    def sign(
        self,
        credential: dict[str, Any],
        *,
        signing_key: SigningKey,
        expires_in_s: int | None = None,
    ) -> str:
        """Wrap a VCDM credential in a VC-JWT, signing via the key backend.

        The raw signature is produced by `signing_key.sign(...)`, so an HSM/Vault
        backend keeps the private key out of this process entirely. The algorithm
        is allow-listed by the shared compact-JWS assembler before signing.
        """
        now = int(time.time())
        issuer = credential.get("issuer")
        issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
        cs = credential.get("credentialSubject")
        subject = cs.get("id") if isinstance(cs, dict) else None   # may be a list of subjects

        payload: dict[str, Any] = {
            "iss": issuer,
            "nbf": now,
            "iat": now,
            "vc": credential,
        }
        if credential.get("id") is not None:      # a null jti fails RFC 7519 (must be a string)
            payload["jti"] = credential["id"]
        if subject:
            payload["sub"] = subject
        if expires_in_s is not None:
            payload["exp"] = now + expires_in_s

        header = {"alg": signing_key.alg, "typ": "JWT", "kid": signing_key.kid}

        from ._jws import sign_compact          # local import breaks the _jws<->vc_jwt cycle
        return sign_compact(header, payload, signing_key=signing_key)

    # -- internals --------------------------------------------------------- #

    @staticmethod
    def _jwk_to_key(jwk: dict[str, Any], alg: str) -> Any:
        try:
            if alg in ("ES256", "ES384"):
                return ECAlgorithm.from_jwk(json.dumps(jwk))
            return OKPAlgorithm.from_jwk(json.dumps(jwk))   # EdDSA
        except Exception as exc:
            raise ProofError(f"could not load {alg} key from JWK: {exc}") from exc

    @staticmethod
    def _reconcile(claims: dict[str, Any], vc: dict[str, Any]) -> tuple[str, str | None]:
        """Enforce W3C VC-JWT envelope/credential consistency (defence in depth)."""
        iss = claims.get("iss")
        if not isinstance(iss, str):        # decode() required "iss"; be explicit
            raise ClaimsInvalid("iss claim is missing or not a string")
        vc_issuer = vc.get("issuer")
        vc_issuer = vc_issuer.get("id") if isinstance(vc_issuer, dict) else vc_issuer
        if vc_issuer and vc_issuer != iss:
            raise ClaimsInvalid(f"iss {iss!r} != vc.issuer {vc_issuer!r}")

        sub = claims.get("sub")
        cs = vc.get("credentialSubject")
        vc_sub = cs.get("id") if isinstance(cs, dict) else None   # may be a list of subjects
        if sub and vc_sub and sub != vc_sub:
            raise ClaimsInvalid(f"sub {sub!r} != credentialSubject.id {vc_sub!r}")

        jti = claims.get("jti")
        if jti and vc.get("id") and jti != vc["id"]:
            raise ClaimsInvalid(f"jti {jti!r} != vc.id {vc['id']!r}")

        subject = sub if isinstance(sub, str) else (vc_sub if isinstance(vc_sub, str) else None)
        return iss, subject

    @staticmethod
    def _check_types(vc: dict[str, Any], expected: list[str]) -> None:
        types = vc.get("type", [])
        if isinstance(types, str):
            types = [types]
        missing = [t for t in expected if t not in types]
        if missing:
            raise ClaimsInvalid(f"credential missing required type(s): {missing}")


__all__ = [
    "ALLOWED_ALGS",
    "ClaimsInvalid",
    "MalformedToken",
    "ProofError",
    "SignatureInvalid",
    "SigningKey",
    "UnsupportedAlgorithm",
    "VcJwtProofSuite",
    "VerifiedCredential",
]
