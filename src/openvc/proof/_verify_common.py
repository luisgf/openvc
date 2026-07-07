"""
openvc.proof._verify_common — cross-suite verification policy checks shared by the
Data Integrity suites (``eddsa-rdfc-2022`` and ``ecdsa-sd-2023``).

Where each cryptosuite owns its signature maths, these checks are suite-agnostic —
a credential's validity window, the meaning of ``proofPurpose``, and the DID
verification-relationship binding do not depend on how the proof was signed. They
run **after** the signature verifies (the fields they read are integrity-protected
by that signature), except the key-selection binding, which necessarily precedes
crypto (you cannot verify without first choosing an authorized key).

The VC-JWT / SD-JWT suites do their own temporal check via the JWT ``exp``/``nbf``
claims; this module is the Data Integrity equivalent, so a proof embedded in the
credential's JSON is held to the same temporal and purpose rules.

Every error here subclasses :class:`~openvc.proof.errors.ProofError`, so a caller
can catch the whole verification-failure family with one ``except``.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ..observability import logger, span
from .errors import (
    CredentialExpired,
    CredentialNotYetValid,
    KeyResolutionError,
    MalformedTimestamp,
    PresentationBindingError,
    ProofMalformed,
    ProofPurposeMismatch,
)

DEFAULT_LEEWAY_S = 60  # tolerance for clock skew, matching the JOSE suites

# Fractional seconds in an XSD/ISO dateTime. Python's fromisoformat only accepted
# exactly 3 or 6 fractional digits before 3.11, so we normalise to microseconds
# (the date has no '.' and a numeric tz offset has none either, so this only ever
# matches the seconds fraction).
_FRACTION = re.compile(r"\.(\d+)")


# The policy-error classes now live in openvc.proof.errors (the canonical proof-error
# home); imported above and re-exported here (and by the suites) for back-compat.


def _parse_ts(value: Any) -> datetime | None:
    """Parse an XSD/ISO-8601 dateTime into an aware UTC datetime, or None if the
    value is absent or unparseable. Normalises the two forms Python's pre-3.11
    ``fromisoformat`` rejects but XSD allows — a trailing ``Z`` and non-3/6-digit
    fractional seconds — so a validity bound is not silently dropped on 3.10/3.11
    (that would be a fail-open expiry bypass). A naive result is assumed UTC."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _bound(document: dict[str, Any], *keys: str) -> datetime | None:
    """The parsed timestamp for the first *keys* the document actually carries,
    honouring precedence (VCDM 2.0 field before its VCDM 1.1 equivalent). A field
    that is **present but unparseable** fails closed (``MalformedTimestamp``)
    rather than being ignored — otherwise an expired credential whose timestamp
    the parser cannot read would verify. An absent field is skipped."""
    for key in keys:
        raw = document.get(key)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        ts = _parse_ts(raw)
        if ts is None:
            raise MalformedTimestamp(f"{key} is not a valid dateTime: {raw!r}")
        return ts
    return None


def check_validity_window(
    document: dict[str, Any],
    proof: dict[str, Any],
    *,
    now: datetime | None,
    leeway_s: int,
) -> None:
    """Enforce the credential's validity window and the proof's own expiry.

    Honours both VCDM 2.0 (``validFrom`` / ``validUntil``) and VCDM 1.1
    (``issuanceDate`` / ``expirationDate``), plus the Data Integrity proof's
    optional ``expires``. *now* pins the evaluation instant (``None`` -> current
    UTC time); pinning it lets a conformance vector or an "as of" audit verify
    deterministically regardless of wall-clock. An absent bound is not a
    violation, but a present-but-unparseable one fails closed (see :func:`_bound`).
    """
    if now is None:
        instant = datetime.now(timezone.utc)
    elif now.tzinfo is None:                      # a naive now is taken as UTC, not
        instant = now.replace(tzinfo=timezone.utc)  # silently as system-local time
    else:
        instant = now.astimezone(timezone.utc)
    leeway = timedelta(seconds=max(0, leeway_s))

    not_before = _bound(document, "validFrom", "issuanceDate")
    if not_before is not None and instant + leeway < not_before:
        raise CredentialNotYetValid(
            f"credential is not valid before {not_before.isoformat()}")

    not_after = _bound(document, "validUntil", "expirationDate")
    if not_after is not None and instant - leeway > not_after:
        raise CredentialExpired(f"credential expired at {not_after.isoformat()}")

    proof_expires = _bound(proof, "expires", "expirationDate")
    if proof_expires is not None and instant - leeway > proof_expires:
        raise CredentialExpired(f"proof expired at {proof_expires.isoformat()}")


def check_proof_purpose(proof: dict[str, Any], expected: str | None) -> None:
    """Require the proof's declared ``proofPurpose`` to equal *expected*. A DI
    proof MUST declare a purpose, so a missing one fails too. *expected* of
    ``None`` disables the check (caller opts out explicitly)."""
    if expected is None:
        return
    actual = proof.get("proofPurpose")
    if actual != expected:
        raise ProofPurposeMismatch(f"proofPurpose {actual!r} != expected {expected!r}")


def check_presentation_binding(
    proof: dict[str, Any], *,
    expected_challenge: str | None,
    expected_domain: str | None,
) -> None:
    """For an ``authentication`` (presentation) proof, bind it to this session and
    audience: the proof's ``challenge`` must equal *expected_challenge* and its
    ``domain`` must include *expected_domain* (anti-replay). Both are integrity-
    protected (part of the signed proof config). ``domain`` may be a string or a
    list; ``None`` on either expectation skips that check."""
    if expected_challenge is not None and proof.get("challenge") != expected_challenge:
        raise PresentationBindingError(
            f"proof challenge {proof.get('challenge')!r} != expected {expected_challenge!r}")
    if expected_domain is not None:
        domain = proof.get("domain")
        ok = domain == expected_domain or (
            isinstance(domain, list) and expected_domain in domain)
        if not ok:
            raise PresentationBindingError(
                f"proof domain {domain!r} does not include expected {expected_domain!r}")


def resolve_verification_key(
    verification_method: Any,
    *,
    proof_purpose: str | None,
    resolver: Any = None,
) -> dict[str, Any]:
    """Resolve the public JWK for *verification_method*, enforcing the DID
    verification-relationship binding for *proof_purpose*.

    Uses *resolver* (a ``DidResolver`` or ``DidResolverRegistry``) when it handles
    the DID, otherwise falls back to offline ``did:key``. When the resolved DID
    document declares the relationship named by *proof_purpose*
    (``assertionMethod`` / ``authentication`` / ...), the method must be listed in
    it — a document that separates an assertion key from an authentication key
    then rejects a proof signed by the wrong one. When the document does not
    declare that relationship at all (a minimal ``did:web`` that only lists
    ``verificationMethod``), the binding cannot be enforced and the key is
    accepted; the ``proofPurpose`` string is still checked separately.
    """
    if not isinstance(verification_method, str) or not verification_method:
        raise KeyResolutionError("proof has no verificationMethod to resolve")

    from ..did.base import DidResolutionError, UnsupportedDidMethod

    did = verification_method.split("#", 1)[0]
    logger.debug("resolve verification method: %s", did)
    doc = None
    with span("openvc.resolve", did=did):
        if resolver is not None:
            supports = getattr(resolver, "supports", None)
            if supports is None or supports(did):
                try:
                    doc = resolver.resolve(did)
                except UnsupportedDidMethod:
                    doc = None
                except DidResolutionError as exc:
                    raise KeyResolutionError(f"could not resolve {did!r}: {exc}") from exc
        if doc is None:
            if not did.startswith("did:key:"):
                raise KeyResolutionError(
                    f"cannot resolve {verification_method!r} offline "
                    f"(pass a resolver, or an injected public_key_jwk)")
            from ..did.did_key import DidKeyResolver
            doc = DidKeyResolver().resolve(did)

    purpose = proof_purpose or "assertionMethod"
    vm = doc.key_for_purpose(verification_method, purpose)
    if vm is None:
        if doc.key_by_kid(verification_method) is None:
            raise KeyResolutionError(
                f"verificationMethod {verification_method!r} not in the DID document")
        raise ProofPurposeMismatch(
            f"verificationMethod {verification_method!r} is not authorized for "
            f"proofPurpose {purpose!r}")
    return vm.public_key_jwk


# JOSE alg -> (JWK kty, JWK crv, hashData digest) for the Data Integrity suites that pick
# their signature algorithm from the *resolved key's* curve rather than from anything in
# the proof. ecdsa-*-2019 is curve-dependent (P-256/SHA-256, P-384/SHA-384 —
# vc-di-ecdsa §3.x); eddsa-* is always SHA-256. Single-sourced here so the curve->digest
# rule cannot drift between the JCS (di_jcs) and RDF (di_ecdsa_rdfc) ECDSA suites.
ALG_PROFILE: dict[str, tuple[str, str, str]] = {
    "EdDSA": ("OKP", "Ed25519", "sha256"),
    "ES256": ("EC", "P-256", "sha256"),
    "ES384": ("EC", "P-384", "sha384"),
}


def match_alg(jwk: dict[str, Any], allowed_algs: frozenset[str], *, cryptosuite: str) -> str:
    """The *allowed_algs* member whose (kty, crv) matches *jwk*, or fail closed.

    Selecting the alg — and thus the hashData digest — from the resolved key's own
    (kty, crv), never from an attacker-controlled proof field, is what lets a suite reject
    a cross-type key (e.g. an Ed25519 OKP key resolved under an ECDSA suite) *before* the
    signature check would read a missing JWK member ('y' on an OKP key) and crash past the
    ProofError contract. The accepted curves are disjoint on ``crv``, so at most one alg
    matches. Shared by the whole-document suites (di_jcs, di_ecdsa_rdfc)."""
    kty, crv = jwk.get("kty"), jwk.get("crv")
    for alg in sorted(allowed_algs):
        p_kty, p_crv, _ = ALG_PROFILE[alg]
        if kty == p_kty and crv == p_crv:
            return alg
    raise ProofMalformed(f"{cryptosuite} does not accept a kty={kty!r} crv={crv!r} key")


__all__ = [
    "ALG_PROFILE",
    "CredentialExpired",
    "CredentialNotYetValid",
    "DEFAULT_LEEWAY_S",
    "KeyResolutionError",
    "MalformedTimestamp",
    "PresentationBindingError",
    "ProofPurposeMismatch",
    "check_presentation_binding",
    "check_proof_purpose",
    "check_validity_window",
    "match_alg",
    "resolve_verification_key",
]
