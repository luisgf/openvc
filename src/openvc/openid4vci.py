"""
openvc.openid4vci — verify a wallet's OpenID4VCI key proof (stateless).

The **issuer-side cryptography** of OpenID for Verifiable Credential Issuance 1.0
(Final, 2025-09-16). Given the Credential Request body a wallet POSTed to a Credential
Endpoint, it:

  1. validates the request shape — ``proofs`` is a JSON object with **exactly one**
     member, the proof type, whose value is a non-empty array of proof values
     (OID4VCI 1.0 §8.2); ``credential_identifier`` and ``credential_configuration_id``
     are mutually exclusive;
  2. verifies every proof in that array as an ``openid4vci-proof+jwt`` (App. F.1) —
     the ``typ`` pin, the algorithm allow-list *before* any crypto, unknown ``crit``,
     **exactly one** of the ``jwk`` / ``kid`` / ``x5c`` header key parameters, the
     signature, the ``aud`` binding to the Credential Issuer Identifier, and ``iat``
     freshness in **both** directions; and
  3. enforces the invariants that only exist across the batch — one shared ``nonce``,
     consumed **exactly once** through the caller's store, and no two proofs bound to
     the same key.

It returns the wallet public key each proof demonstrated possession of, which is what
:meth:`openvc.proof.sd_jwt.SdJwtVcProofSuite.issue` wants as ``holder_jwk``.

This is deliberately **not** an OpenID4VCI server. It builds no Credential Response,
publishes no metadata, mints no ``c_nonce``, pre-authorized code, ``transaction_id`` or
``notification_id``, runs no endpoint, and integrates no Authorization Server — those
have a lifetime, a socket or a deployment policy, and belong to the issuing application
(ADR-0007). openvc handles bytes that are signed, or that must be shaped byte-exactly
per spec; anything with a lifetime belongs to your AS.

**Nonce state is the caller's**, injected as :data:`ConsumeNonce`. It is *required* by
default: replay is the property a key proof exists to defend, and a plain
``expected_nonce`` string could not express "consume once, atomically" — a caller
comparing after the fact would have verified a signature and *not* the replay property.
The callable is invoked once per request, **after** every signature has verified, so an
unauthenticated attacker cannot burn nonces by spraying garbage.

Key attestations (App. D) are **parsed, bound, and not trusted**. Parsed:
:func:`peek_key_attestation` reads one without verifying it, and a proof's attestation
reaches :data:`ResolveProofKeyInContext` already parsed, because the key that signed an
attested proof lives *inside the header* and a caller must not need a second decoder to
find it. Bound: App. D's MUST — the proof is signed by a key the attestation contains —
is enforced. Not trusted: the attestation's signature is never checked and no
wallet-provider anchor is consulted, so **the binding check stops no attacker** (whoever
forges a proof also chooses its attestation, and simply lists their own key); it catches
an honest wallet, or the caller's own resolver, producing a key the wallet never
claimed. Which key in ``attested_keys`` a ``kid`` names is **not** specified by the
spec — the example uses an index, wallets also use the JWK's own ``kid`` or a
thumbprint — so that mapping is the caller's, never a guess made here.

Scope: the ``jwt`` proof type only. The ``attestation`` proof type, ``di_vp`` and
OpenID Federation ``trust_chain`` proof keys raise a typed
:class:`UnsupportedProofType`. What this supports claiming is *OpenID4VCI 1.0 key-proof
verification* — not "issuance", and not HAIP, which additionally requires DPoP, key
attestation *trust* and client authentication, all of them downstream.
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from .errors import OpenvcError
from .keys import MLDSA_ALGS, InvalidKey, jwk_thumbprint
from .proof._jws import parse_compact, verify_compact
from .proof._verify_common import DEFAULT_LEEWAY_S, check_jwt_temporal, reject_unknown_crit
from .proof.errors import ClaimsInvalid, MalformedToken, UnsupportedAlgorithm
from .proof.vc_jwt import ALLOWED_ALGS

__all__ = [
    "verify_credential_request_proofs",
    "parse_credential_request",
    "peek_proof_header",
    "peek_key_attestation",
    "CredentialRequest",
    "VerifiedProof",
    "UnverifiedKeyAttestation",
    "ProofKeyContext",
    "ConsumeNonce",
    "ResolveProofKey",
    "ResolveProofKeyInContext",
    "OpenID4VCIError",
    "CredentialRequestMalformed",
    "UnsupportedProofType",
    "ProofReplayed",
    "PROOF_TYPE_JWT",
    "PROOF_TYP",
    "KEY_ATTESTATION_TYP",
    "DEFAULT_PROOF_MAX_AGE_S",
    "MAX_PROOF_BYTES",
    "MAX_KEY_ATTESTATION_BYTES",
]

# OID4VCI 1.0 App. F: the only proof type this module verifies.
PROOF_TYPE_JWT = "jwt"

# App. F.1 pins `typ` to "openid4vci-proof+jwt". RFC 7515 §4.1.9 makes omitting the
# "application/" prefix a *media-type equivalence*, not an algorithm widening, so both
# spellings are accepted — the same rule as the SD-JWT issuer `typ`.
PROOF_TYP = frozenset({"openid4vci-proof+jwt", "application/openid4vci-proof+jwt"})

# App. D pins a key attestation's `typ` the same way. Exposed rather than enforced by
# `peek_key_attestation`: pinning `typ` is a verifier's job, and that verifier — the one
# that would also check the signature against a wallet-provider anchor — is downstream.
KEY_ATTESTATION_TYP = frozenset({"key-attestation+jwt", "application/key-attestation+jwt"})

# How old a proof's `iat` may be. A key proof is a freshness artifact: the wallet mints
# one per request, so minutes are generous.
DEFAULT_PROOF_MAX_AGE_S = 300

# A proof value is a compact JWS carrying a public key, not a document. Cap it before
# any parsing so a hostile request cannot make us allocate — the `jwe.MAX_JWE_BYTES`
# pattern.
MAX_PROOF_BYTES = 16 * 1024

# `peek_key_attestation` is a public entry point taking a caller-supplied string, so it
# needs its own cap; an attestation reached through a proof is already inside the
# `MAX_PROOF_BYTES` one.
MAX_KEY_ATTESTATION_BYTES = 16 * 1024

# The header key parameters App. F.1 defines. Exactly one must be present: two lets an
# attacker pair a `kid` naming an honest key with a `jwk` they control, and any
# implementation that "prefers" one silently accepts.
#
# `key_attestation` is deliberately NOT one of them. It carries `attested_keys`, but
# selecting one of those keys means trusting an unverified blob to say which key signed
# the proof, and App. F.1 fixes no rule for how a `kid` names an entry (its own example
# uses an index; wallets also use the JWK's `kid` member or an RFC 7638 thumbprint).
# So a header carrying only `key_attestation` and no key parameter is rejected below,
# and a caller that knows its ecosystem's rule supplies the key via
# `resolve_proof_key_in_context`.
_KEY_PARAMS = ("jwk", "kid", "x5c", "trust_chain")

# JOSE alg -> the (kty, crv) a key must have to be used with it. Binding these before
# the signature check is what stops an `alg: ES256` header pointing at an Ed25519 JWK,
# where the outcome would otherwise depend on the backend's own validation.
_ALG_KEY_BINDING = {
    "EdDSA": ("OKP", "Ed25519"),
    "Ed25519": ("OKP", "Ed25519"),        # RFC 9864 fully-specified name
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
}

# Members that must never appear in a proof's `jwk`: their presence means a wallet is
# leaking a private key, or is probing for a backend that would use it.
_PRIVATE_JWK_MEMBERS = frozenset({"d", "k", "p", "q", "dp", "dq", "qi", "priv"})


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class OpenID4VCIError(OpenvcError):
    """Base class for OpenID4VCI issuer-side failures."""


class CredentialRequestMalformed(OpenID4VCIError):
    """The Credential Request shape is invalid (not the §8.2 wire contract)."""


class UnsupportedProofType(OpenID4VCIError):
    """A proof type or key parameter this verifier does not implement."""


class ProofReplayed(OpenID4VCIError):
    """The nonce was already consumed (or the caller's store rejected it).

    Distinct from :class:`~openvc.proof.errors.ClaimsInvalid` so a Credential Endpoint
    can answer OID4VCI ``invalid_nonce`` — hand the wallet a fresh ``c_nonce`` and let
    it retry — rather than rejecting the wallet outright.
    """


# --------------------------------------------------------------------------- #
# Injected state and I/O (openvc stores none of it)
# --------------------------------------------------------------------------- #

ConsumeNonce = Callable[[str], bool]
"""Atomically mark a ``c_nonce`` used, and report whether it was valid.

The Credential Issuer's nonce state is the **caller's** — openvc stores nothing. The
callable MUST be atomic (a Redis ``SET key val NX``, a SQL ``DELETE … RETURNING``):
return ``True`` only if the nonce existed, had not expired, and *this* call is the one
that consumed it. Return anything falsey to reject.

A read-then-write store is not sufficient: two concurrent requests would both observe
the nonce as unused. :class:`openvc.cache.TtlCache` is **not** suitable either — it
documents its own lack of single-flight, which is benign for a read cache and fatal for
a single-use token.

Invoked exactly once per Credential Request, **after** every proof signature has
verified.
"""

ResolveProofKey = Callable[[str], dict]
"""Map a proof JWT's ``kid`` header to the wallet's public JWK.

Injected because resolving a ``kid`` is deployment policy (a wallet-provider registry, a
prior enrolment record). Absent, a ``kid``-keyed proof is rejected — fail closed.

Sees the ``kid`` and nothing else. When the key is carried *in the header* — the
attested-key form, ``{typ, alg, kid, key_attestation}`` — use
:data:`ResolveProofKeyInContext` instead.
"""

ResolveProofKeyInContext = Callable[["ProofKeyContext"], dict]
"""Map a proof to the wallet's public JWK, with everything openvc knows at that point.

The same job as :data:`ResolveProofKey` — and mutually exclusive with it; passing both
is a caller error — but taking a :class:`ProofKeyContext` rather than a bare ``kid``.
Needed for the attested-key form, where the key that signed the proof is in the header's
``key_attestation`` and a bare ``kid`` names it under a rule only the caller's ecosystem
knows::

    def resolve(ctx):
        keys = ctx.key_attestation.attested_keys if ctx.key_attestation else ()
        return keys[int(ctx.kid)]        # or match ctx.kid against each key's own "kid"

Takes a context *object*, not more parameters, so growing what a resolver can see never
breaks the ones already written.

Everything in the context is **unverified** — no signature has been checked when it is
called. Use it to *select* a key, never to decide the key is trustworthy.
"""


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedProof:
    """One **verified** key proof from a Credential Request's ``proofs`` array.

    ``public_jwk`` is the key the issued Credential must be bound to — hand it straight
    to :meth:`~openvc.proof.sd_jwt.SdJwtVcProofSuite.issue` as ``holder_jwk``.

    ``key_attestation`` is the header's attestation JWT captured **verbatim and
    unverified** (the ``peek_*`` doctrine): it must never drive a trust decision. Its
    contents are :func:`peek_key_attestation`'s to read; that the proof key is one of
    its ``attested_keys`` has been checked, that the attestation itself is genuine has
    **not**.
    """
    public_jwk: dict[str, Any] = field(default_factory=dict)
    thumbprint: str = ""                       # RFC 7638, base64url SHA-256
    alg: str = ""
    key_source: str = ""                       # "jwk" | "kid" | "x5c"
    issued_at: int = 0                         # the proof's `iat`
    nonce: str | None = None
    client_id: str | None = None               # the proof's `iss`, when present
    key_attestation: str | None = None         # UNVERIFIED
    header: Mapping[str, Any] = field(default_factory=dict)
    claims: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UnverifiedKeyAttestation:
    """A key attestation JWT (App. D) parsed **without** verifying it. UNTRUSTED.

    Named for what it is not. Its signature has not been checked, no wallet-provider
    anchor has been consulted, and ``key_storage`` / ``user_authentication`` /
    ``status`` are the wallet's own claims about itself. **Structure is validated,
    trust is not**: the shape App. D fixes is enforced so this object is predictable,
    and everything a verifier would decide is left on ``header`` and ``claims``.

    The one thing openvc does with it is *negative*: reject a proof whose key is not in
    ``attested_keys`` (App. D's MUST). See :func:`peek_key_attestation`.
    """
    attested_keys: tuple[Mapping[str, Any], ...] = ()
    key_storage: tuple[str, ...] = ()
    user_authentication: tuple[str, ...] = ()
    certification: str | None = None           # a URL, unfetched
    nonce: str | None = None
    status: Mapping[str, Any] | None = None
    issued_at: int | None = None               # the attestation's `iat`
    expires_at: int | None = None              # the attestation's `exp`
    header: Mapping[str, Any] = field(default_factory=dict)
    claims: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProofKeyContext:
    """What openvc knows about one key proof at key-resolution time. All UNVERIFIED.

    Handed to :data:`ResolveProofKeyInContext`. No signature has been checked yet — by
    construction, since the point is to find the key that will check it — so this is
    material for *selecting* a key and never grounds for trusting one.

    ``header`` is a read-only copy: a resolver cannot reach back and change what the
    rest of the verification then sees.
    """
    kid: str | None = None
    alg: str = ""
    header: Mapping[str, Any] = field(default_factory=dict)
    key_attestation: UnverifiedKeyAttestation | None = None
    credential_issuer: str = ""                # what this proof's `aud` must equal
    index: int = 0                             # position in the request's `proofs` array


@dataclass(frozen=True)
class CredentialRequest:
    """A shape-validated OID4VCI 1.0 §8.2 Credential Request.

    **Not** verified: ``proofs`` holds the raw, untrusted proof values. Pass this (or
    the raw body) to :func:`verify_credential_request_proofs`.
    """
    credential_configuration_id: str | None = None
    credential_identifier: str | None = None
    proof_type: str | None = None              # the single member name of `proofs`
    proofs: tuple[str, ...] = ()
    response_encryption: Mapping[str, Any] | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Request shape (OID4VCI 1.0 §8.2)
# --------------------------------------------------------------------------- #

def parse_credential_request(
    body: Mapping[str, Any] | str,
    *,
    batch_size: int | None = None,
    supported_configuration_ids: Sequence[str] | None = None,
) -> CredentialRequest:
    """Validate the Credential Request wire contract and return it structured.

    *batch_size* caps ``len(proofs)``; it defaults to **1**, so an issuer that never
    advertised ``batch_credential_issuance`` rejects a batch instead of minting one
    credential per proof off a single grant. *supported_configuration_ids*, when given,
    pins ``credential_configuration_id`` to what this issuer actually offers.

    Raises :class:`CredentialRequestMalformed` on any shape violation — a malformed
    request fails safe rather than being silently narrowed.
    """
    body = _as_mapping(body, "Credential Request")
    limit = 1 if batch_size is None else batch_size
    if limit < 1:
        raise CredentialRequestMalformed("batch_size must be at least 1")

    config_id = body.get("credential_configuration_id")
    identifier = body.get("credential_identifier")
    if (config_id is None) == (identifier is None):
        raise CredentialRequestMalformed(
            "Credential Request needs exactly one of credential_configuration_id "
            "or credential_identifier")
    for name, value in (("credential_configuration_id", config_id),
                        ("credential_identifier", identifier)):
        if value is not None and (not isinstance(value, str) or not value):
            raise CredentialRequestMalformed(f"{name} must be a non-empty string")
    if (config_id is not None and supported_configuration_ids is not None
            and config_id not in supported_configuration_ids):
        raise CredentialRequestMalformed(
            f"unsupported credential_configuration_id {config_id!r}")

    proof_type, proofs = _parse_proofs(body.get("proofs"), limit)

    encryption = body.get("credential_response_encryption")
    if encryption is not None and not isinstance(encryption, Mapping):
        raise CredentialRequestMalformed(
            "credential_response_encryption must be an object")

    return CredentialRequest(
        credential_configuration_id=config_id,
        credential_identifier=identifier,
        proof_type=proof_type,
        proofs=proofs,
        response_encryption=encryption,
        raw=body,
    )


def _parse_proofs(proofs: Any, limit: int) -> tuple[str, tuple[str, ...]]:
    """The ``proofs`` object: exactly one member, a non-empty array of proof values.

    OID4VCI 1.0 §8.2 removed the singular ``proof`` parameter; ``proofs`` is an object
    keyed by proof type. Allowing more than one member would let a wallet offer a type
    we verify alongside one we do not, and leave the choice to us.

    §8.2 lets each proof type define its own element type — ``jwt`` is a string, ``di_vp``
    is a JSON object — so a non-string element under a *different* type is an unsupported
    type, not a malformed request. Both fail closed; only the signal differs, and it is
    the one a Credential Endpoint maps to ``invalid_proof``.
    """
    if not isinstance(proofs, Mapping):
        raise CredentialRequestMalformed("Credential Request needs a proofs object")
    if len(proofs) != 1:
        raise CredentialRequestMalformed(
            f"proofs must carry exactly one proof type, got {len(proofs)}")
    proof_type = next(iter(proofs))
    values = proofs[proof_type]
    if not isinstance(proof_type, str) or not proof_type:
        raise CredentialRequestMalformed("proofs key must be a non-empty string")
    if not isinstance(values, (list, tuple)) or not values:
        raise CredentialRequestMalformed(
            f"proofs[{proof_type!r}] must be a non-empty array")
    if len(values) > limit:
        raise CredentialRequestMalformed(
            f"proofs[{proof_type!r}] has {len(values)} entries, batch limit is {limit}")
    for value in values:
        if not isinstance(value, str) or not value:
            if proof_type != PROOF_TYPE_JWT:
                raise UnsupportedProofType(
                    f"proof type {proof_type!r} is not supported (only 'jwt')")
            raise CredentialRequestMalformed(
                f"proofs[{proof_type!r}] entries must be non-empty strings")
        if len(value.encode("utf-8")) > MAX_PROOF_BYTES:
            raise CredentialRequestMalformed(
                f"proofs[{proof_type!r}] entry exceeds {MAX_PROOF_BYTES} bytes")
    return proof_type, tuple(values)


def _as_mapping(value: Mapping[str, Any] | str, subject: str) -> Mapping[str, Any]:
    """Accept a parsed object or a JSON string, fail closed on anything else."""
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        raise CredentialRequestMalformed(f"{subject} must be an object or a JSON string")
    try:
        parsed = json.loads(value)
    except (ValueError, RecursionError) as exc:      # RecursionError: hostile nesting
        raise CredentialRequestMalformed(f"{subject} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CredentialRequestMalformed(f"{subject} must be a JSON object")
    return parsed


# --------------------------------------------------------------------------- #
# Reading before trusting (the `peek_*` doctrine)
# --------------------------------------------------------------------------- #

def peek_proof_header(proof: str) -> Mapping[str, Any]:
    """A key proof's protected header, read **without** verifying anything. UNTRUSTED.

    Exposed so that a caller who must look at a proof before verification — to pick a
    registry, to find the ``key_attestation`` — uses *this* parse rather than writing a
    second one. Two notions of what a header is can disagree; one cannot.

    Read-only, and never a trust decision: the bytes are the wallet's, unauthenticated.
    """
    if not isinstance(proof, str):
        raise MalformedToken("key proof must be a compact JWS string")
    if len(proof.encode("utf-8")) > MAX_PROOF_BYTES:
        raise MalformedToken(f"key proof exceeds {MAX_PROOF_BYTES} bytes")
    header, _, _, _ = parse_compact(proof)
    return MappingProxyType(dict(header))


def peek_key_attestation(attestation: str) -> UnverifiedKeyAttestation:
    """Parse a key attestation JWT (OID4VCI 1.0 App. D) **without** verifying it.

    Returns an :class:`UnverifiedKeyAttestation` — read its docstring before using
    anything it holds. **Structure is validated, trust is not**: ``attested_keys`` must
    be a non-empty array of JWK objects and the other App. D members must have their
    documented types, because a caller reading a predictable object is the whole point;
    but ``typ``, ``exp`` and the signature are *not* checked, because those are a
    verifier's decisions and that verifier needs a wallet-provider trust anchor openvc
    has no model for (ADR-0007 D9).

    Raises :class:`~openvc.proof.errors.MalformedToken` if it is not a compact JWS, and
    :class:`~openvc.proof.errors.ClaimsInvalid` if it is one but not shaped like a key
    attestation.
    """
    if not isinstance(attestation, str):
        raise MalformedToken("key attestation must be a compact JWS string")
    if len(attestation.encode("utf-8")) > MAX_KEY_ATTESTATION_BYTES:
        raise MalformedToken(
            f"key attestation exceeds {MAX_KEY_ATTESTATION_BYTES} bytes")
    header, claims, _, _ = parse_compact(attestation)

    keys = claims.get("attested_keys")
    if not isinstance(keys, (list, tuple)) or not keys:
        raise ClaimsInvalid("key attestation attested_keys must be a non-empty array")
    for key in keys:
        if not isinstance(key, Mapping):
            raise ClaimsInvalid("key attestation attested_keys entries must be JWK objects")

    return UnverifiedKeyAttestation(
        attested_keys=tuple(MappingProxyType(dict(key)) for key in keys),
        key_storage=_attestation_strings(claims.get("key_storage"), "key_storage"),
        user_authentication=_attestation_strings(
            claims.get("user_authentication"), "user_authentication"),
        certification=_attestation_string(claims.get("certification"), "certification"),
        nonce=_attestation_string(claims.get("nonce"), "nonce"),
        status=_attestation_object(claims.get("status")),
        issued_at=_attestation_timestamp(claims.get("iat"), "iat"),
        expires_at=_attestation_timestamp(claims.get("exp"), "exp"),
        header=MappingProxyType(dict(header)),
        claims=MappingProxyType(dict(claims)),
    )


def _attestation_strings(value: Any, name: str) -> tuple[str, ...]:
    """An App. D array-of-strings member: absent, or a non-empty array of strings."""
    if value is None:
        return ()
    if (not isinstance(value, (list, tuple)) or not value
            or not all(isinstance(item, str) for item in value)):
        raise ClaimsInvalid(
            f"key attestation {name} must be a non-empty array of strings when present")
    return tuple(value)


def _attestation_string(value: Any, name: str) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise ClaimsInvalid(f"key attestation {name} must be a string when present")


def _attestation_object(value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ClaimsInvalid("key attestation status must be an object when present")
    return MappingProxyType(dict(value))


def _attestation_timestamp(value: Any, name: str) -> int | None:
    """`iat`/`exp` are read but **not** enforced — only their type is pinned.

    Whether an attestation has expired is a verifier's call, and the verifier that
    would make it also checks the signature. Rejecting a non-numeric one here only
    stops a caller from comparing a string against a clock.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ClaimsInvalid(
            f"key attestation {name} must be a finite numeric timestamp when present")
    return int(value)


# --------------------------------------------------------------------------- #
# Key-proof verification (OID4VCI 1.0 App. F.1)
# --------------------------------------------------------------------------- #

def verify_credential_request_proofs(
    request: CredentialRequest | Mapping[str, Any] | str,
    *,
    credential_issuer: str,
    check_nonce: ConsumeNonce | None = None,
    require_nonce: bool = True,
    expected_client_id: str | None = None,
    resolve_proof_key: ResolveProofKey | None = None,
    resolve_proof_key_in_context: ResolveProofKeyInContext | None = None,
    trust_anchors: Sequence[Any] | None = None,
    max_age_s: int = DEFAULT_PROOF_MAX_AGE_S,
    leeway_s: int = DEFAULT_LEEWAY_S,
    now: datetime | None = None,
    allowed_algs: frozenset[str] = ALLOWED_ALGS,
    batch_size: int | None = None,
) -> tuple[VerifiedProof, ...]:
    """Verify every key proof in a Credential Request; return what each demonstrated.

    *credential_issuer* is the Credential Issuer Identifier each proof's ``aud`` must
    equal. *check_nonce* consumes the ``c_nonce`` (see :data:`ConsumeNonce`) and is
    required unless *require_nonce* is explicitly ``False``. *resolve_proof_key* — or
    *resolve_proof_key_in_context*, which additionally sees the header and its parsed
    key attestation, and which is the one the attested-key form needs — and
    *trust_anchors* enable the ``kid`` and ``x5c`` key parameters respectively; without
    them, proofs using those parameters are rejected. Passing both resolvers is a caller
    error. *expected_client_id*, when given, pins the proof's ``iss``. *now* pins the
    instant for deterministic tests.

    When a proof carries ``key_attestation``, App. D's MUST is enforced: the key that
    signed it must be one of the attestation's ``attested_keys``. That check **stops no
    attacker** — the attestation is unsigned as far as openvc is concerned, so a forger
    lists their own key — and exists to catch an honest wallet, or *this call's own
    resolver*, producing a key the wallet never claimed. Trusting the attestation is
    downstream work and needs a wallet-provider anchor.

    **Any failure rejects the whole request** — there is no partial issuance. Raises
    :class:`CredentialRequestMalformed`, :class:`UnsupportedProofType`,
    :class:`ProofReplayed`, or the shared proof errors
    (:class:`~openvc.proof.errors.ClaimsInvalid`,
    :class:`~openvc.proof.errors.SignatureInvalid`,
    :class:`~openvc.proof.errors.MalformedToken`,
    :class:`~openvc.proof.errors.UnsupportedAlgorithm`).
    """
    if not isinstance(credential_issuer, str) or not credential_issuer:
        raise CredentialRequestMalformed("credential_issuer must be a non-empty string")
    if require_nonce and check_nonce is None:
        # Fail closed rather than verify a signature and skip the replay property.
        raise ClaimsInvalid(
            "a nonce is required but no check_nonce was given to consume it; pass "
            "check_nonce, or set require_nonce=False to opt out explicitly")
    if max_age_s < 0 or leeway_s < 0:
        raise CredentialRequestMalformed("max_age_s and leeway_s must not be negative")
    if resolve_proof_key is not None and resolve_proof_key_in_context is not None:
        # Two resolvers means a precedence between them, and a silent precedence among
        # key sources is the defect this verifier is built to refuse (see _KEY_PARAMS).
        raise CredentialRequestMalformed(
            "pass resolve_proof_key or resolve_proof_key_in_context, not both")

    if not isinstance(request, CredentialRequest):
        request = parse_credential_request(request, batch_size=batch_size)
    if request.proof_type != PROOF_TYPE_JWT:
        raise UnsupportedProofType(
            f"proof type {request.proof_type!r} is not supported (only 'jwt')")

    current = int(time.time()) if now is None else int(now.timestamp())
    verified = tuple(
        _verify_one_proof(
            value,
            credential_issuer=credential_issuer,
            expected_client_id=expected_client_id,
            resolve_proof_key=resolve_proof_key,
            resolve_proof_key_in_context=resolve_proof_key_in_context,
            trust_anchors=trust_anchors,
            max_age_s=max_age_s,
            leeway_s=leeway_s,
            current=current,
            now=now,
            allowed_algs=allowed_algs,
            index=index,
        )
        for index, value in enumerate(request.proofs)
    )

    _check_batch_invariants(verified, check_nonce=check_nonce, require_nonce=require_nonce)
    return verified


def _check_batch_invariants(
    verified: tuple[VerifiedProof, ...], *,
    check_nonce: ConsumeNonce | None,
    require_nonce: bool,
) -> None:
    """The invariants that only exist across the whole request.

    Deliberately not reachable per-proof: consuming the nonce inside the loop would
    fail the second proof of a batch, and a caller looping over a public singular
    verifier would reintroduce exactly that. Hence no public singular verifier.
    """
    nonces = {proof.nonce for proof in verified}
    if len(nonces) != 1:
        raise ClaimsInvalid(
            "all key proofs in a Credential Request must carry the same nonce")
    nonce = nonces.pop()
    if require_nonce and nonce is None:
        raise ClaimsInvalid("key proof is missing the required nonce")

    thumbprints = [proof.thumbprint for proof in verified]
    if len(set(thumbprints)) != len(thumbprints):
        # N credentials must mean N keys; otherwise a wallet gets N copies bound to one.
        raise ClaimsInvalid("two key proofs in the batch are bound to the same key")

    # Last, and exactly once: every signature above has verified, so an unauthenticated
    # attacker cannot reach this and burn a nonce.
    if nonce is not None and check_nonce is not None:
        if not check_nonce(nonce):
            raise ProofReplayed(f"nonce {nonce!r} was already consumed or is unknown")


def _verify_one_proof(
    proof: str, *,
    credential_issuer: str,
    expected_client_id: str | None,
    resolve_proof_key: ResolveProofKey | None,
    resolve_proof_key_in_context: ResolveProofKeyInContext | None,
    trust_anchors: Sequence[Any] | None,
    max_age_s: int,
    leeway_s: int,
    current: int,
    now: datetime | None,
    allowed_algs: frozenset[str],
    index: int,
) -> VerifiedProof:
    """One ``openid4vci-proof+jwt``, structure and allow-lists before any crypto."""
    header, _, _, _ = parse_compact(proof)

    typ = header.get("typ")
    if typ not in PROOF_TYP:
        # Type confusion is the attack: without this pin a KB-JWT, a VP-JWT, an ID
        # token or a status-list token could be replayed as a key proof.
        raise ClaimsInvalid(f"key proof typ must be openid4vci-proof+jwt, got {typ!r}")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed_algs:
        raise UnsupportedAlgorithm(f"key proof alg {alg!r} is not allow-listed")
    reject_unknown_crit(header)

    # Parsed here, not read at the end: the key resolver needs it (in the attested-key
    # form the signing key is *inside* it), and a malformed attestation must reject the
    # proof before any crypto, like every other structure rule (ADR-0007 D5).
    attestation_jwt = header.get("key_attestation")
    if attestation_jwt is not None and not isinstance(attestation_jwt, str):
        raise ClaimsInvalid("key_attestation header must be a string when present")
    attestation = (
        peek_key_attestation(attestation_jwt) if attestation_jwt is not None else None)

    public_jwk, key_source = _proof_key(
        header, alg=alg, resolve_proof_key=resolve_proof_key,
        resolve_proof_key_in_context=resolve_proof_key_in_context,
        attestation=attestation, credential_issuer=credential_issuer, index=index,
        trust_anchors=trust_anchors, now=now)

    thumbprint = _thumbprint(public_jwk, "the key proof's key")
    if attestation is not None:
        _check_attested_key(thumbprint, attestation)

    # Re-parses and re-checks alg/crit; that redundancy is deliberate — one audited
    # entry point for every signature in the library.
    _, claims = verify_compact(proof, public_key_jwk=public_jwk, allowed_algs=allowed_algs)

    _check_audience(claims.get("aud"), credential_issuer)
    issued_at = _check_freshness(
        claims.get("iat"), max_age_s=max_age_s, leeway_s=leeway_s, current=current)
    check_jwt_temporal(claims, leeway_s=leeway_s, subject="key proof", now=current)

    client_id = claims.get("iss")
    if client_id is not None and not isinstance(client_id, str):
        raise ClaimsInvalid("key proof iss must be a string when present")
    if expected_client_id is not None and client_id != expected_client_id:
        raise ClaimsInvalid(
            f"key proof iss {client_id!r} does not match the authenticated client")

    nonce = claims.get("nonce")
    if nonce is not None and (not isinstance(nonce, str) or not nonce):
        raise ClaimsInvalid("key proof nonce must be a non-empty string when present")

    return VerifiedProof(
        public_jwk=public_jwk,
        thumbprint=thumbprint,
        alg=alg,
        key_source=key_source,
        issued_at=issued_at,
        nonce=nonce,
        client_id=client_id,
        key_attestation=attestation_jwt,   # UNVERIFIED — peek doctrine
        header=header,
        claims=claims,
    )


def _proof_key(
    header: Mapping[str, Any], *,
    alg: str,
    resolve_proof_key: ResolveProofKey | None,
    resolve_proof_key_in_context: ResolveProofKeyInContext | None,
    attestation: UnverifiedKeyAttestation | None,
    credential_issuer: str,
    index: int,
    trust_anchors: Sequence[Any] | None,
    now: datetime | None,
) -> tuple[dict[str, Any], str]:
    """The wallet's public key, from **exactly one** header key parameter."""
    present = [name for name in _KEY_PARAMS if header.get(name) is not None]
    if len(present) != 1:
        # Zero means there is no key. Two lets an attacker pair a `kid` naming an
        # honest key with a `jwk` they control, and be accepted by any implementation
        # that silently prefers one of them.
        raise ClaimsInvalid(
            f"key proof must carry exactly one of {'/'.join(_KEY_PARAMS)}, got {present}")
    source = present[0]

    if source == "jwk":
        jwk = header["jwk"]
        if not isinstance(jwk, Mapping):
            raise ClaimsInvalid("key proof jwk header must be an object")
        leaked = sorted(_PRIVATE_JWK_MEMBERS.intersection(jwk))
        if leaked:
            raise ClaimsInvalid(f"key proof jwk carries private members {leaked}")
        jwk = dict(jwk)
        _check_key_binds_to_alg(jwk, alg)
        return jwk, source

    if source == "x5c":
        if not trust_anchors:
            # An unanchored chain is decoration, not trust.
            raise ClaimsInvalid(
                "key proof uses x5c but no trust_anchors were given to validate it")
        from . import x5c as _x5c
        chain = _x5c.load_x5c_chain(header["x5c"])
        # Deliberately not resolve_x5c_key: its iss->SAN binding and P-256-only leaf
        # rule are issuer-certificate rules; a wallet key certificate binds differently.
        # `now` is threaded through so a caller that pins the instant pins the chain's
        # validity window too — otherwise a frozen-clock verification would silently
        # path-validate against the real wall clock.
        _x5c.validate_cert_chain(
            chain[0], chain[1:], trust_anchors=trust_anchors, now=now)
        jwk = _x5c.leaf_public_jwk(chain[0])
        _check_key_binds_to_alg(jwk, alg)
        return jwk, source

    if source == "kid":
        kid = header["kid"]
        if not isinstance(kid, str) or not kid:
            raise ClaimsInvalid("key proof kid header must be a non-empty string")
        if resolve_proof_key_in_context is not None:
            # The header is copied read-only: a resolver cannot reach back and change
            # what the attestation binding and `VerifiedProof.header` then report.
            jwk = resolve_proof_key_in_context(ProofKeyContext(
                kid=kid, alg=alg, header=MappingProxyType(dict(header)),
                key_attestation=attestation, credential_issuer=credential_issuer,
                index=index))
            resolver = "resolve_proof_key_in_context"
        elif resolve_proof_key is not None:
            jwk = resolve_proof_key(kid)
            resolver = f"resolve_proof_key({kid!r})"
        else:
            raise ClaimsInvalid(
                "key proof uses kid but no resolve_proof_key was given to resolve it "
                "(or resolve_proof_key_in_context, if the key is in the header's "
                "key_attestation)")
        if not isinstance(jwk, Mapping):
            raise ClaimsInvalid(f"{resolver} did not return a JWK")
        jwk = dict(jwk)
        _check_key_binds_to_alg(jwk, alg)
        return jwk, source

    raise UnsupportedProofType(
        "OpenID Federation trust_chain proof keys are not supported")


def _thumbprint(jwk: Mapping[str, Any], subject: str) -> str:
    """RFC 7638, with :class:`~openvc.keys.InvalidKey` mapped into this module's errors.

    ``InvalidKey`` is a key-backend error, not a :class:`~openvc.proof.errors.ProofError`,
    so letting it out would hand a Credential Endpoint an exception type this module
    does not document — over bytes a wallet chose. `_check_key_binds_to_alg` does not
    prevent it: it reads ``kty``/``crv`` and never the coordinates.
    """
    try:
        return jwk_thumbprint(jwk)
    except InvalidKey as exc:
        raise ClaimsInvalid(f"{subject} cannot be thumbprinted: {exc}") from exc


def _check_attested_key(thumbprint: str, attestation: UnverifiedKeyAttestation) -> None:
    """App. D: the proof MUST be signed by a key the attestation contains.

    A **conformance** check, not a defence, and the difference matters. Whoever forges
    a proof also chooses its ``key_attestation``, whose signature nothing here verifies,
    so a forger simply attests their own key: this stops no attacker. What it catches is
    an honest wallet, or the caller's own resolver, producing a key the wallet never
    claimed — a wrong-key issuance that would otherwise verify cleanly.

    That an unverified blob may drive it at all rests on the direction: it can only
    *reject* a proof, never accept one.
    """
    if any(_thumbprint(key, "an attested key") == thumbprint
           for key in attestation.attested_keys):
        return
    raise ClaimsInvalid(
        "the key that signed this proof is not among the key attestation's "
        "attested_keys (compared by RFC 7638 thumbprint — note that a JWK whose "
        "coordinates are not fixed-width per RFC 7518 §6.2.1.2 thumbprints differently "
        "from the same key encoded correctly)")


def _check_key_binds_to_alg(jwk: Mapping[str, Any], alg: str) -> None:
    """The key's type must match the header ``alg``, before the signature is checked.

    Otherwise an ``alg: ES256`` header pointing at an Ed25519 JWK reaches the backend
    and the outcome depends on that backend's own validation rather than on us.
    """
    binding = _ALG_KEY_BINDING.get(alg)
    if binding is not None:
        kty, crv = binding
        if jwk.get("kty") != kty or jwk.get("crv") != crv:
            raise ClaimsInvalid(
                f"key proof alg {alg} needs a kty={kty} crv={crv} key, got "
                f"kty={jwk.get('kty')!r} crv={jwk.get('crv')!r}")
        return
    if alg in MLDSA_ALGS:                    # only reachable via a widened allowed_algs
        if jwk.get("kty") != "AKP" or jwk.get("alg") != alg:
            raise ClaimsInvalid(f"key proof alg {alg} needs a matching AKP key")
        return
    raise UnsupportedAlgorithm(f"key proof alg {alg!r} has no key binding rule")


def _check_audience(aud: Any, credential_issuer: str) -> None:
    """``aud`` must be the Credential Issuer Identifier, and nothing else.

    A single-element array is accepted as the JWT spelling of one audience. A
    multi-valued ``aud`` is **rejected** — deliberately stricter than RFC 7519, because
    a proof audienced at several issuers is a cross-issuer replay vector by
    construction.
    """
    if isinstance(aud, str):
        values = [aud]
    elif isinstance(aud, (list, tuple)):
        values = list(aud)
    else:
        raise ClaimsInvalid("key proof aud must be a string or an array")
    if len(values) != 1:
        raise ClaimsInvalid(
            f"key proof aud must name exactly one audience, got {len(values)}")
    if values[0] != credential_issuer:
        raise ClaimsInvalid(
            f"key proof aud {values[0]!r} is not this Credential Issuer "
            f"{credential_issuer!r}")


def _check_freshness(iat: Any, *, max_age_s: int, leeway_s: int, current: int) -> int:
    """``iat`` freshness, in **both** directions.

    ``check_jwt_temporal`` covers ``exp``/``nbf`` and never looks at ``iat``, but a key
    proof's whole purpose is freshness, and wallets are not required to set ``exp``.

    The future-dated direction is the one implementations forget: without it a wallet
    signs once with ``iat = now + 10y`` and holds a proof that never goes stale. The
    non-finite guard matters for the same reason it does in ``check_jwt_temporal`` —
    ``json.loads`` accepts ``NaN``, and every comparison against it is ``False``, i.e.
    *never stale*.
    """
    if iat is None:
        raise ClaimsInvalid("key proof is missing the required iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)) or not math.isfinite(iat):
        raise ClaimsInvalid("key proof iat must be a finite numeric timestamp")
    if current - iat > max_age_s + leeway_s:
        raise ClaimsInvalid("key proof is too old")
    if iat - current > leeway_s:
        raise ClaimsInvalid("key proof iat is in the future")
    return int(iat)
