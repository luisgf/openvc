"""
openvc.proof.data_integrity — Data Integrity proof suite, cryptosuite
``eddsa-rdfc-2022`` (W3C VC Data Integrity + EdDSA Cryptosuites).

The second proof profile alongside :mod:`openvc.proof.vc_jwt`. Where VC-JWT wraps
a credential in a JOSE token, a Data Integrity proof is **embedded** in the
credential's own JSON as a ``proof`` object, and integrity is computed over the
RDF canonical form (RDFC-1.0 / URDNA2015) rather than the raw bytes — so it
survives re-serialization.

Algorithm (vc-di-eddsa §3.3, eddsa-rdfc-2022):

  1. proofConfig = the proof object without ``proofValue``, carrying the
     document's ``@context``; canonicalize to N-Quads, SHA-256 it.
  2. the unsecured document (``proof`` removed); canonicalize, SHA-256 it.
  3. hashData = proofConfigHash ‖ documentHash  (64 bytes).
  4. Ed25519-sign hashData; ``proofValue = 'z' + base58btc(signature)``.

Signing goes through the :class:`~openvc.proof.vc_jwt.SigningKey` protocol (so an
HSM/Vault Ed25519 key drops in). Requires the optional ``pyld`` dependency (the
``[data-integrity]`` extra) for canonicalization; importing this module without
it is fine, only sign/verify need it.
"""
from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from ..multibase import decode_multibase, encode_multibase
from ._verify_common import (
    DEFAULT_LEEWAY_S,
    CredentialExpired,
    CredentialNotYetValid,
    KeyResolutionError,
    MalformedTimestamp,
    PresentationBindingError,
    ProofPurposeMismatch,
    check_presentation_binding,
    check_proof_purpose,
    check_validity_window,
    resolve_verification_key,
)
from .contexts import DocumentLoaderError, document_loader
from .errors import ProofError, ProofMalformed, SignatureInvalid, UnsupportedCryptosuite
from .vc_jwt import SigningKey

CRYPTOSUITE = "eddsa-rdfc-2022"
PROOF_TYPE = "DataIntegrityProof"
_ED25519_ALG = "EdDSA"


# The shared leaves (SignatureInvalid / ProofMalformed / UnsupportedCryptosuite) are
# imported from openvc.proof.errors; DataIntegrityError stays as this suite's own
# error for Data-Integrity-specific failures (canonicalization, key shape).
class DataIntegrityError(ProofError): ...


# The post-signature policy failures verify() may raise beyond signature/format
# errors, re-exported here so callers catch them from the suite they use. All
# share the ProofError base, so one `except ProofError` still catches everything.
POLICY_ERRORS = (
    CredentialExpired, CredentialNotYetValid, MalformedTimestamp,
    ProofPurposeMismatch, KeyResolutionError, PresentationBindingError,
)


@dataclass(frozen=True)
class VerifiedDataIntegrity:
    credential: dict[str, Any]     # the secured document (proof included)
    issuer: str | None
    subject: str | None
    proof: dict[str, Any]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_pyld() -> Any:
    try:
        from pyld import jsonld
    except ImportError as exc:                       # pragma: no cover - env dependent
        raise DataIntegrityError(
            "Data Integrity needs the pyld JSON-LD processor: "
            "pip install 'openvc-core[data-integrity]'") from exc
    return jsonld


def _canonize(document: dict[str, Any], loader: Any) -> bytes:
    jsonld = _require_pyld()
    try:
        nquads = jsonld.normalize(
            document,
            {"algorithm": "URDNA2015", "format": "application/n-quads",
             "documentLoader": loader})
    except Exception as exc:
        # pyld wraps a loader refusal in its own JsonLdError; surface the clear
        # "unbundled context" error if it caused this, else wrap generically.
        cause: BaseException | None = exc
        for _ in range(8):
            if isinstance(cause, DocumentLoaderError):
                raise cause
            if cause is None:
                break
            cause = cause.__cause__ or cause.__context__
        raise DataIntegrityError(f"canonicalization failed: {exc}") from exc
    return nquads.encode("utf-8")


def _hash_data(document: dict[str, Any], proof_config: dict[str, Any], loader: Any) -> bytes:
    # proofConfig hash first, then document hash (vc-di-eddsa §3.3.1).
    cfg_hash = hashlib.sha256(_canonize(proof_config, loader)).digest()
    doc_hash = hashlib.sha256(_canonize(document, loader)).digest()
    return cfg_hash + doc_hash


def _unsecured(document: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in document.items() if k != "proof"}


class DataIntegrityProofSuite:
    """Sign and verify credentials with an embedded eddsa-rdfc-2022 proof."""

    def __init__(self, *, leeway_s: int = DEFAULT_LEEWAY_S) -> None:
        self._leeway = leeway_s

    def add_proof(
        self,
        credential: dict[str, Any],
        *,
        signing_key: SigningKey,
        verification_method: str,
        proof_purpose: str = "assertionMethod",
        challenge: str | None = None,
        domain: str | None = None,
        created: datetime | None = None,
        extra_contexts: Mapping[str, dict] | None = None,
    ) -> dict[str, Any]:
        """Return a copy of *credential* secured with a Data Integrity proof.

        *verification_method* is embedded verbatim (a did:key / did:web URL a
        verifier can resolve). For a presentation proof (``proof_purpose=
        "authentication"``) pass *challenge* / *domain* to bind it to a verifier
        session; both are covered by the signature. The input is not mutated.
        """
        if signing_key.alg != _ED25519_ALG:
            raise UnsupportedCryptosuite(
                f"eddsa-rdfc-2022 requires an Ed25519 (EdDSA) key, got "
                f"{signing_key.alg!r}")
        if "@context" not in credential:
            raise ProofMalformed("credential has no @context to canonicalize against")
        if "proof" in credential:
            raise ProofMalformed("credential already carries a proof")

        proof = {
            "type": PROOF_TYPE,
            "cryptosuite": CRYPTOSUITE,
            "created": _iso(created if created is not None else datetime.now(timezone.utc)),
            "verificationMethod": verification_method,
            "proofPurpose": proof_purpose,
        }
        if challenge is not None:
            proof["challenge"] = challenge
        if domain is not None:
            proof["domain"] = domain
        proof_config = dict(proof)
        proof_config["@context"] = credential["@context"]

        loader = document_loader(extra_contexts)
        data = _hash_data(_unsecured(credential), proof_config, loader)
        signature = signing_key.sign(data)           # raw 64-byte Ed25519

        secured = copy.deepcopy(credential)
        secured["proof"] = dict(proof, proofValue=encode_multibase(signature))
        return secured

    def verify(
        self,
        secured: dict[str, Any],
        *,
        public_key_jwk: dict[str, Any] | None = None,
        resolver: Any = None,
        expected_proof_purpose: str | None = "assertionMethod",
        expected_challenge: str | None = None,
        expected_domain: str | None = None,
        now: datetime | None = None,
        extra_contexts: Mapping[str, dict] | None = None,
    ) -> VerifiedDataIntegrity:
        """Verify the embedded proof end to end.

        Key selection: with *public_key_jwk* the proof must verify against that
        operator-trusted key; otherwise the key is resolved from the proof's
        ``verificationMethod`` — via *resolver* (a ``DidResolver`` /
        ``DidResolverRegistry``, e.g. to reach ``did:web``) when given, falling
        back to offline ``did:key``. A resolved key must be authorized by the DID
        document for *expected_proof_purpose*.

        Policy (checked after the signature verifies): the proof's
        ``proofPurpose`` must equal *expected_proof_purpose* (pass ``None`` to
        skip), and the credential's validity window
        (``validFrom``/``validUntil`` or ``issuanceDate``/``expirationDate``) plus
        the proof's ``expires`` must contain *now* (default: current time) within
        the suite's leeway.
        """
        proof = secured.get("proof")
        if not isinstance(proof, dict):
            raise ProofMalformed("credential has no proof object")
        if proof.get("type") != PROOF_TYPE:
            raise ProofMalformed(f"unexpected proof type {proof.get('type')!r}")
        if proof.get("cryptosuite") != CRYPTOSUITE:
            raise UnsupportedCryptosuite(
                f"unsupported cryptosuite {proof.get('cryptosuite')!r}")
        proof_value = proof.get("proofValue")
        if not isinstance(proof_value, str):
            raise ProofMalformed("proof has no proofValue")

        try:
            signature = decode_multibase(proof_value)
        except Exception as exc:
            raise ProofMalformed(f"invalid proofValue: {exc}") from exc

        proof_config = {k: v for k, v in proof.items() if k != "proofValue"}
        proof_config["@context"] = secured.get("@context")

        loader = document_loader(extra_contexts)
        unsecured = _unsecured(secured)
        data = _hash_data(unsecured, proof_config, loader)

        jwk = public_key_jwk or resolve_verification_key(
            proof.get("verificationMethod"),
            proof_purpose=proof.get("proofPurpose"),
            resolver=resolver,
        )
        if not _verify_ed25519(jwk, data, signature):
            raise SignatureInvalid("Data Integrity proof does not verify")

        check_proof_purpose(proof, expected_proof_purpose)
        check_presentation_binding(
            proof, expected_challenge=expected_challenge, expected_domain=expected_domain)
        check_validity_window(unsecured, proof, now=now, leeway_s=self._leeway)

        issuer = secured.get("issuer")
        issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
        subject = (secured.get("credentialSubject") or {})
        subject_id = subject.get("id") if isinstance(subject, dict) else None
        return VerifiedDataIntegrity(
            credential=secured, issuer=issuer, subject=subject_id, proof=proof)


def _verify_ed25519(jwk: dict[str, Any], data: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        raise ProofMalformed("public key is not an Ed25519 (OKP) JWK")
    import base64
    try:
        raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        public_key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:                # bad base64 / wrong key length
        raise ProofMalformed(f"malformed Ed25519 public key: {exc}") from exc
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


__all__ = [
    "CRYPTOSUITE",
    "CredentialExpired",
    "CredentialNotYetValid",
    "DataIntegrityError",
    "DataIntegrityProofSuite",
    "KeyResolutionError",
    "MalformedTimestamp",
    "POLICY_ERRORS",
    "PROOF_TYPE",
    "PresentationBindingError",
    "ProofMalformed",
    "ProofPurposeMismatch",
    "SignatureInvalid",
    "UnsupportedCryptosuite",
    "VerifiedDataIntegrity",
]
