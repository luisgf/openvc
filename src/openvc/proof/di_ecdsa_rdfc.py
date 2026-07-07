"""
openvc.proof.di_ecdsa_rdfc — the ECDSA RDF Data Integrity cryptosuite
``ecdsa-rdfc-2019`` (W3C *VC Data Integrity ECDSA Cryptosuites v1.0*).

The ECDSA analogue of :class:`~openvc.proof.data_integrity.DataIntegrityProofSuite`
(``eddsa-rdfc-2022``): same **RDF N-Quads** canonicalization (RDFC-1.0 / URDNA2015,
via ``pyld``) and the same config-first ``hashData`` ::

    hashData = H(canonicalize(proofConfig)) ‖ H(canonicalize(unsecuredDocument))

but it signs **ECDSA** instead of Ed25519 — **P-256/SHA-256** (``ES256``) or
**P-384/SHA-384** (``ES384``), raw R‖S like the JOSE path, the digest chosen by the
key's curve (vc-di-ecdsa §3.x). It is to ``eddsa-rdfc-2022`` what
:class:`~openvc.proof.di_jcs.EcdsaJcsProofSuite` (``ecdsa-jcs-2019``) is to
``eddsa-jcs-2022``, only over RDF rather than JCS — so it reuses the RDF
canonicalization helpers from :mod:`openvc.proof.data_integrity` and the
multi-curve ECDSA key handling shape from :mod:`openvc.proof.di_jcs`.

Signing goes through the :class:`~openvc.proof.vc_jwt.SigningKey` protocol (so an
HSM/Vault P-256/P-384 key drops in). Like the RDF ``eddsa-rdfc-2022`` path — and
unlike the JCS suites — it needs the optional ``pyld`` dependency (the
``[data-integrity]`` extra) for canonicalization; importing this module without it
is fine, only sign/verify need it.
"""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from ..errors import OpenvcError
from ..keys import verify_signature
from ..multibase import decode_multibase, encode_multibase
from ._verify_common import (
    DEFAULT_LEEWAY_S,
    check_presentation_binding,
    check_proof_purpose,
    check_validity_window,
    resolve_verification_key,
)
from .contexts import document_loader
from .data_integrity import PROOF_TYPE, VerifiedDataIntegrity, _canonize, _iso, _unsecured
from .errors import ProofMalformed, SignatureInvalid, UnsupportedCryptosuite
from .vc_jwt import SigningKey

__all__ = ["EcdsaRdfcProofSuite", "ECDSA_RDFC_CRYPTOSUITE"]

ECDSA_RDFC_CRYPTOSUITE = "ecdsa-rdfc-2019"

# JOSE alg -> (JWK kty, JWK crv, hashData digest). ecdsa-rdfc-2019 is curve-dependent:
# P-256 hashes with SHA-256, P-384 with SHA-384 (vc-di-ecdsa §3.x — the same rule the
# JCS ecdsa-jcs-2019 sibling uses). The digest is used for BOTH halves of hashData. The
# two curves are disjoint on ``crv``, so a resolved key maps to exactly one alg.
_ALG_PROFILE: dict[str, tuple[str, str, str]] = {
    "ES256": ("EC", "P-256", "sha256"),
    "ES384": ("EC", "P-384", "sha384"),
}
_ALLOWED_ALGS = frozenset(_ALG_PROFILE)


def _hash_data(
    unsecured: dict[str, Any], proof_config: dict[str, Any], loader: Any, hash_name: str,
) -> bytes:
    """``hashData = H(canonicalize(proofConfig)) ‖ H(canonicalize(unsecuredDocument))``
    where ``H`` is *hash_name* (SHA-256 for P-256, SHA-384 for P-384), config first.

    Identical shape to the ``eddsa-rdfc-2022`` suite's ``_hash_data`` — the only
    differences are the curve-dependent digest and that both halves are ECDSA-signed —
    so a proof produced here verifies against any conforming ``ecdsa-rdfc-2019``
    implementation. A document that cannot be RDF-canonicalized (an unbundled
    ``@context``, a malformed node) already fails **closed** inside ``_canonize`` as a
    typed :class:`~openvc.proof.data_integrity.DataIntegrityError` /
    ``DocumentLoaderError`` rather than leaking a bare ``pyld`` error.
    """
    digest = getattr(hashlib, hash_name)
    cfg_hash = digest(_canonize(proof_config, loader)).digest()
    doc_hash = digest(_canonize(unsecured, loader)).digest()
    return cfg_hash + doc_hash


class EcdsaRdfcProofSuite:
    """Sign and verify credentials with an embedded ``ecdsa-rdfc-2019`` proof.

    Whole-document (non-selective) ECDSA Data Integrity over RDF N-Quads —
    **P-256/SHA-256** (``ES256``) or **P-384/SHA-384** (``ES384``), selected by the
    signing/verification key's curve. The RDF sibling of
    :class:`~openvc.proof.di_jcs.EcdsaJcsProofSuite`; needs ``pyld`` (the
    ``[data-integrity]`` extra), which the JCS suite does not.
    """

    _allowed_algs = _ALLOWED_ALGS

    def __init__(self, *, leeway_s: int = DEFAULT_LEEWAY_S) -> None:
        self._leeway = leeway_s

    def _match_alg(self, jwk: dict[str, Any]) -> str:
        """The allowed alg whose (kty, crv) matches *jwk*, or fail closed.

        Picking the alg from the key's curve — not from anything attacker-controlled —
        both selects the right digest and rejects a cross-type key (e.g. an Ed25519 OKP
        key resolved under this ecdsa suite) *before* :func:`verify_signature` would read
        a missing JWK member (an OKP key has no ``y``) and crash past the ProofError
        contract.
        """
        kty, crv = jwk.get("kty"), jwk.get("crv")
        for alg in sorted(self._allowed_algs):
            p_kty, p_crv, _ = _ALG_PROFILE[alg]
            if kty == p_kty and crv == p_crv:
                return alg
        raise ProofMalformed(
            f"{ECDSA_RDFC_CRYPTOSUITE} does not accept a kty={kty!r} crv={crv!r} key")

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
        """Return a copy of *credential* secured with an ``ecdsa-rdfc-2019`` proof.

        *verification_method* is embedded verbatim (a did:key / did:web URL a verifier
        can resolve). For a presentation proof (``proof_purpose="authentication"``) pass
        *challenge* / *domain* to bind it to a verifier session; both are covered by the
        signature. The input is not mutated. Like the ``eddsa-rdfc-2022`` suite this
        canonicalizes over RDF, so any non-bundled ``@context`` term must be supplied via
        *extra_contexts*.
        """
        if signing_key.alg not in self._allowed_algs:
            raise UnsupportedCryptosuite(
                f"{ECDSA_RDFC_CRYPTOSUITE} requires one of {sorted(self._allowed_algs)}, "
                f"got {signing_key.alg!r}")
        if "@context" not in credential:
            raise ProofMalformed("credential has no @context to canonicalize against")
        if "proof" in credential:
            raise ProofMalformed("credential already carries a proof")

        proof: dict[str, Any] = {
            "type": PROOF_TYPE,
            "cryptosuite": ECDSA_RDFC_CRYPTOSUITE,
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
        hash_name = _ALG_PROFILE[signing_key.alg][2]
        data = _hash_data(_unsecured(credential), proof_config, loader, hash_name)
        signature = signing_key.sign(data)           # raw ES256 / ES384 R‖S

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
        """Verify the embedded ``ecdsa-rdfc-2019`` proof end to end.

        Key selection, proof-purpose authorization, presentation binding and the
        validity window behave exactly as
        :meth:`~openvc.proof.data_integrity.DataIntegrityProofSuite.verify`; only the
        signature algebra (ECDSA, curve chosen by the resolved key) differs. The
        curve-selected digest and the accepted JWK ``kty``/``crv`` follow from the key
        via ``_match_alg``, so a cross-type key fails closed before the crypto runs.
        """
        proof = secured.get("proof")
        if not isinstance(proof, dict):
            raise ProofMalformed("credential has no proof object")
        if proof.get("type") != PROOF_TYPE:
            raise ProofMalformed(f"unexpected proof type {proof.get('type')!r}")
        if proof.get("cryptosuite") != ECDSA_RDFC_CRYPTOSUITE:
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
        jwk = public_key_jwk or resolve_verification_key(
            proof.get("verificationMethod"),
            proof_purpose=proof.get("proofPurpose"),
            resolver=resolver,
        )
        # The resolved key's (kty, crv) picks the alg + digest — and rejects a cross-type
        # key before verify_signature would read a wrong JWK member and crash.
        alg = self._match_alg(jwk)
        data = _hash_data(unsecured, proof_config, loader, _ALG_PROFILE[alg][2])
        try:
            ok = verify_signature(
                alg=alg, public_jwk=jwk, signing_input=data, signature=signature)
        except (OpenvcError, ValueError, KeyError) as exc:   # e.g. wrong-length R‖S, bad key
            raise SignatureInvalid(
                f"{ECDSA_RDFC_CRYPTOSUITE} proof does not verify: {exc}") from exc
        if not ok:
            raise SignatureInvalid(f"{ECDSA_RDFC_CRYPTOSUITE} proof does not verify")

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
