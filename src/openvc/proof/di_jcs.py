"""
openvc.proof.di_jcs — the JCS Data Integrity cryptosuites (``eddsa-jcs-2022`` and
``ecdsa-jcs-2019``).

Same Data Integrity flow as :mod:`openvc.proof.data_integrity` — ::

    hashData = SHA-256(canonicalize(proofConfig)) ‖ SHA-256(canonicalize(unsecuredDocument))

sign it, embed the signature as a multibase ``proofValue`` — but the canonical
form is **RFC 8785 JCS** (:mod:`openvc.proof._jcs`) instead of RDF N-Quads. That
makes these a whole-document Data Integrity path with **no ``pyld`` dependency**:
the JCS suites canonicalize pure-stdlib. ``eddsa-jcs-2022`` signs Ed25519;
``ecdsa-jcs-2019`` signs ECDSA P-256 over SHA-256 (raw R‖S, like the JOSE path).

The two suites share every step except the key algorithm, so they are one base
class parameterised by ``(_cryptosuite, _alg)``; :class:`DataIntegrityProofSuite`
(the RDF ``eddsa-rdfc-2022`` path, pinned byte-for-byte to the W3C vectors) is left
untouched.
"""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from typing import Any

from ..errors import OpenvcError
from ..keys import verify_signature
from ..multibase import decode_multibase, encode_multibase
from ._jcs import JcsError, canonicalize
from ._verify_common import (
    DEFAULT_LEEWAY_S,
    check_presentation_binding,
    check_proof_purpose,
    check_validity_window,
    resolve_verification_key,
)
from .data_integrity import PROOF_TYPE, VerifiedDataIntegrity, _iso, _unsecured
from .errors import ProofMalformed, SignatureInvalid, UnsupportedCryptosuite
from .vc_jwt import SigningKey

__all__ = [
    "EddsaJcsProofSuite",
    "EcdsaJcsProofSuite",
    "EDDSA_JCS_CRYPTOSUITE",
    "ECDSA_JCS_CRYPTOSUITE",
]

EDDSA_JCS_CRYPTOSUITE = "eddsa-jcs-2022"
ECDSA_JCS_CRYPTOSUITE = "ecdsa-jcs-2019"


def _hash_data(unsecured: dict[str, Any], proof_config: dict[str, Any]) -> bytes:
    """``hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsecuredDocument))``.

    Identical shape to the RDF suite's ``_hash_data``, only the canonicalizer
    differs — so a proof produced here verifies against any implementation that
    reads eddsa-jcs-2022 / ecdsa-jcs-2019.

    A document that cannot be JCS-canonicalized — a non-finite number (``json``
    accepts ``NaN``/``Infinity`` by default), a non-JSON value type, or hostile
    deep nesting — fails **closed** as :class:`ProofMalformed` rather than leaking a
    bare ``JcsError`` / ``RecursionError`` past the ``ProofError`` contract.
    """
    try:
        return (hashlib.sha256(canonicalize(proof_config)).digest()
                + hashlib.sha256(canonicalize(unsecured)).digest())
    except (JcsError, RecursionError, ValueError, TypeError) as exc:
        raise ProofMalformed(f"document is not JCS-canonicalizable: {exc}") from exc


class _JcsProofSuite:
    """Shared machinery for the JCS Data Integrity cryptosuites.

    Subclasses set ``_cryptosuite`` (the ``proof.cryptosuite`` string), ``_alg`` (the
    JOSE alg the signing/verification key must use), and ``_kty``/``_crv`` (the JWK
    key type the resolved verification key must be — checked before verifying so a
    cross-type key, e.g. an Ed25519 key under an ``ecdsa`` cryptosuite, fails closed
    instead of crashing inside the verifier).
    """

    _cryptosuite: str
    _alg: str
    _kty: str
    _crv: str

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
    ) -> dict[str, Any]:
        """Return a copy of *credential* secured with a JCS Data Integrity proof.

        *verification_method* is embedded verbatim (a did:key / did:web URL a
        verifier can resolve). For a presentation proof (``proof_purpose=
        "authentication"``) pass *challenge* / *domain* to bind it to a verifier
        session; both are covered by the signature. The input is not mutated.
        Unlike the RDF suite this needs no ``@context`` term resolution, but the
        document must still carry ``@context`` — it is canonicalized (and signed)
        as an ordinary member, so tampering with it breaks the proof.
        """
        if signing_key.alg != self._alg:
            raise UnsupportedCryptosuite(
                f"{self._cryptosuite} requires a {self._alg} key, got {signing_key.alg!r}")
        if "@context" not in credential:
            raise ProofMalformed("credential has no @context")
        if "proof" in credential:
            raise ProofMalformed("credential already carries a proof")

        proof: dict[str, Any] = {
            "type": PROOF_TYPE,
            "cryptosuite": self._cryptosuite,
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

        data = _hash_data(_unsecured(credential), proof_config)
        signature = signing_key.sign(data)           # raw Ed25519 (64B) or ES256 R‖S (64B)

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
    ) -> VerifiedDataIntegrity:
        """Verify the embedded JCS proof end to end.

        Key selection, proof-purpose authorization, presentation binding and the
        validity window behave exactly as :meth:`DataIntegrityProofSuite.verify`;
        only the canonicalization (JCS, not RDF) and the accepted ``cryptosuite``
        differ.
        """
        proof = secured.get("proof")
        if not isinstance(proof, dict):
            raise ProofMalformed("credential has no proof object")
        if proof.get("type") != PROOF_TYPE:
            raise ProofMalformed(f"unexpected proof type {proof.get('type')!r}")
        if proof.get("cryptosuite") != self._cryptosuite:
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

        unsecured = _unsecured(secured)
        data = _hash_data(unsecured, proof_config)

        jwk = public_key_jwk or resolve_verification_key(
            proof.get("verificationMethod"),
            proof_purpose=proof.get("proofPurpose"),
            resolver=resolver,
        )
        # The resolved key must match the suite's curve — otherwise verify_signature
        # would read the wrong JWK members (e.g. an OKP key has no "y") and crash.
        if jwk.get("kty") != self._kty or jwk.get("crv") != self._crv:
            raise ProofMalformed(
                f"{self._cryptosuite} needs a {self._crv} key, got "
                f"kty={jwk.get('kty')!r} crv={jwk.get('crv')!r}")
        try:
            ok = verify_signature(
                alg=self._alg, public_jwk=jwk, signing_input=data, signature=signature)
        except (OpenvcError, ValueError, KeyError) as exc:   # e.g. wrong-length R‖S, bad key
            raise SignatureInvalid(
                f"{self._cryptosuite} proof does not verify: {exc}") from exc
        if not ok:
            raise SignatureInvalid(f"{self._cryptosuite} proof does not verify")

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


class EddsaJcsProofSuite(_JcsProofSuite):
    """Data Integrity ``eddsa-jcs-2022``: Ed25519 over RFC 8785 JCS (no ``pyld``)."""

    _cryptosuite = EDDSA_JCS_CRYPTOSUITE
    _alg = "EdDSA"
    _kty = "OKP"
    _crv = "Ed25519"


class EcdsaJcsProofSuite(_JcsProofSuite):
    """Data Integrity ``ecdsa-jcs-2019``: ECDSA P-256 / SHA-256 over RFC 8785 JCS.

    Whole-document (non-selective) ECDSA Data Integrity, and — unlike its
    selective-disclosure sibling :mod:`openvc.proof.ecdsa_sd` — needs no ``pyld``.
    P-384 is out of scope (that would widen the JOSE alg allow-list beyond
    ``{ES256, EdDSA}``); a non-P-256 key is rejected as :class:`ProofMalformed`.
    """

    _cryptosuite = ECDSA_JCS_CRYPTOSUITE
    _alg = "ES256"
    _kty = "EC"
    _crv = "P-256"
