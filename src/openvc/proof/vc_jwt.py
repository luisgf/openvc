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
* Algorithm allow-list is fixed (ES256, ES384, EdDSA, and the RFC 9864
  fully-specified name Ed25519, which is EdDSA over Ed25519). `alg: none`, RS*, HS*
  are rejected before any crypto runs — this is the primary defence against
  alg-confusion. (ES384 is the P-384 leg of the Data Integrity ecdsa-*-2019 suites;
  it does not change the EBSI/EUDI-preferred ES256 path. IANA deprecated the
  polymorphic "EdDSA" in RFC 9864, so "Ed25519" is accepted alongside it — see the
  versioning guide for the migration.)
* The verification algorithm is taken from the token header ONLY after checking it
  against the allow-list, and is then pinned when calling the verifier.
* peek_issuer never influences verification; it exists solely to select a key.
"""

from __future__ import annotations

import base64
import json
import math
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
from ._verify_common import check_validity_window

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

ALLOWED_ALGS: frozenset[str] = frozenset({"ES256", "ES384", "EdDSA", "Ed25519"})

# EXPERIMENTAL post-quantum algs (RFC 9964). NEVER in the default allow-list — merged in
# only when a suite is constructed with allow_pq=True (ADR-0004 D5). The alg-confusion
# defence is unchanged for everyone else: the allow-list check still runs before crypto,
# and opting in adds ONLY these three names, never the classic weak algs.
ALLOWED_ALGS_PQ: frozenset[str] = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
DEFAULT_LEEWAY_S = 60  # tolerance for clock skew on exp/nbf/iat

# PyJWT (2.x) ships only the polymorphic "EdDSA"; teach a PRIVATE PyJWT instance the
# RFC 9864 fully-specified "Ed25519" name (same OKP/Ed25519 verification) so a token
# with `alg: Ed25519` verifies without mutating the process-global pyjwt registry.
_JWT = pyjwt.PyJWT()
_JWT._jws.register_algorithm("Ed25519", OKPAlgorithm())


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
        """The JOSE algorithm identifier — ``"ES256"``, ``"ES384"``, ``"EdDSA"`` or
        the RFC 9864 fully-specified ``"Ed25519"``."""
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

    def __init__(self, *, leeway_s: int = DEFAULT_LEEWAY_S, allow_pq: bool = False) -> None:
        self._leeway = leeway_s
        # allow_pq merges the EXPERIMENTAL ML-DSA algs into this suite's allow-list; the
        # default suite rejects ML-DSA at the allow-list, before any crypto (ADR-0004).
        self._algs = ALLOWED_ALGS | ALLOWED_ALGS_PQ if allow_pq else ALLOWED_ALGS

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
        if alg not in self._algs:                          # allow-list BEFORE crypto
            raise UnsupportedAlgorithm(f"algorithm {alg!r} is not permitted")

        if alg in ALLOWED_ALGS_PQ:
            # ML-DSA is not a PyJWT algorithm — verify the signature through the
            # dependency-light primitive and validate the JWT claims ourselves.
            claims = self._verify_mldsa(token, alg, public_key_jwk, audience)
        else:
            key = self._jwk_to_key(public_key_jwk, alg)
            try:
                claims = _JWT.decode(                      # PyJWT instance that knows "Ed25519"
                    token,
                    key=key,
                    algorithms=[alg],                     # pinned, single alg
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
            except (pyjwt.PyJWTError, OverflowError) as exc:  # +Inf exp -> OverflowError in PyJWT
                raise ClaimsInvalid(str(exc)) from exc

        credential = claims.get("vc")
        if not isinstance(credential, dict):
            raise ClaimsInvalid("no embedded `vc` object in token")

        # Defence in depth: also honour the credential body's own validity window
        # (VCDM 2.0 validFrom/validUntil, VCDM 1.1 issuanceDate/expirationDate). The JWT
        # nbf/exp checked above is the primary temporal gate, but an issuer — EBSI's
        # VCDM 2.0 envelopes among them — may encode expiry ONLY in the credential body;
        # without this an expired such credential would still verify. Same leeway; there
        # is no Data-Integrity proof object on the JOSE path, so pass an empty one.
        check_validity_window(credential, {}, now=None, leeway_s=self._leeway)

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
        return sign_compact(header, payload, signing_key=signing_key, allowed_algs=self._algs)

    # -- internals --------------------------------------------------------- #

    def _verify_mldsa(
        self, token: str, alg: str, public_key_jwk: dict[str, Any], audience: str | None,
    ) -> dict[str, Any]:
        """Verify an ML-DSA VC-JWT: signature via the dependency-light primitive (PyJWT
        has no ML-DSA), then the JWT claims validated here."""
        from ..keys import KeyBackendError, verify_signature
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError as exc:
            raise MalformedToken("not a compact JWS (need three parts)") from exc
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            signature = _b64url_decode(sig_b64)
            payload = _b64url_decode(payload_b64)
        except (ValueError, TypeError) as exc:
            raise MalformedToken("token is not valid base64url") from exc
        try:
            ok = verify_signature(alg=alg, public_jwk=public_key_jwk,
                                  signing_input=signing_input, signature=signature)
        except KeyBackendError as exc:                 # malformed/mismatched AKP JWK, or
            raise SignatureInvalid(                    # ML-DSA unavailable -> typed ProofError
                f"could not verify {alg} signature: {exc}") from exc
        if not ok:
            raise SignatureInvalid(f"{alg} signature does not verify")
        try:
            claims = json.loads(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            raise MalformedToken("payload is not valid JSON") from exc
        if not isinstance(claims, dict):
            raise ClaimsInvalid("JWT payload must be a JSON object")
        self._check_jwt_claims(claims, audience)
        return claims

    def _check_jwt_claims(self, claims: dict[str, Any], audience: str | None) -> None:
        # Mirror the PyJWT gate for the ML-DSA path: require iss, enforce exp/nbf with the
        # suite leeway, check aud when expected. Fail closed and typed.
        if not isinstance(claims.get("iss"), str):
            raise ClaimsInvalid("the 'iss' claim is required")
        now = int(time.time())
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if exp is not None:
            # NaN/Inf survive isinstance(float) and make every comparison False (never
            # expires) — reject non-finite, as the PyJWT path does (RFC 7519 NumericDate).
            if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
                raise ClaimsInvalid("'exp' must be a finite numeric date")
            if now > exp + self._leeway:
                raise ClaimsInvalid("token has expired")
        if nbf is not None:
            if isinstance(nbf, bool) or not isinstance(nbf, (int, float)) or not math.isfinite(nbf):
                raise ClaimsInvalid("'nbf' must be a finite numeric date")
            if now < nbf - self._leeway:
                raise ClaimsInvalid("token is not yet valid")
        if audience is not None:
            aud = claims.get("aud")
            auds = aud if isinstance(aud, list) else [aud]
            if audience not in auds:
                raise ClaimsInvalid("audience mismatch")

    @staticmethod
    def _jwk_to_key(jwk: dict[str, Any], alg: str) -> Any:
        # openvc's OKP support is Ed25519-only: pin the curve BEFORE loading so
        # neither the RFC 9864 fully-specified "Ed25519" name (whose whole point is
        # that the curve is fixed) nor the polymorphic "EdDSA" can verify against a
        # non-Ed25519 OKP key (e.g. an Ed448 verificationMethod). Without this, PyJWT's
        # OKPAlgorithm would accept any OKP curve — disagreeing with the curve-pinned
        # openvc.keys.verify_signature used by the SD-JWT / VP / status paths.
        if alg in ("EdDSA", "Ed25519") and (
                jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519"):
            raise ProofError(f"{alg} requires an OKP Ed25519 key, got "
                             f"kty={jwk.get('kty')!r} crv={jwk.get('crv')!r}")
        try:
            if alg in ("ES256", "ES384"):
                return ECAlgorithm.from_jwk(json.dumps(jwk))
            return OKPAlgorithm.from_jwk(json.dumps(jwk))   # EdDSA / Ed25519 (Ed25519 only)
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
    "ALLOWED_ALGS_PQ",
    "ClaimsInvalid",
    "MalformedToken",
    "ProofError",
    "SignatureInvalid",
    "SigningKey",
    "UnsupportedAlgorithm",
    "VcJwtProofSuite",
    "VerifiedCredential",
]
