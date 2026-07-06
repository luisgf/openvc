"""
openvc.status.issue — issuer-side status-list construction.

The check side (:func:`~openvc.status.status_list.check_credential_status`,
:func:`~openvc.status.token_status_list.check_token_status`) *reads* a status
list; this is the other half — building the artifacts an issuer publishes and
updates in order to revoke:

* :func:`build_status_list_credential` — a W3C **BitstringStatusListCredential**
  (the VC that wraps an ``encodedList``), returned UNSIGNED so the caller secures
  it with whichever proof suite it already uses (``VcJwtProofSuite.sign`` or
  ``DataIntegrityProofSuite.add_proof``): the status list is an ordinary VC.
* :func:`build_status_list_token` / :func:`verify_status_list_token` — an IETF
  **status-list token** (``typ: statuslist+jwt``), signed and verified through the
  shared JOSE path (allow-listed ``{ES256, EdDSA}``).
* :func:`build_status_list_entry` / :func:`build_token_status_reference` — the tiny
  pointer an issuer embeds in each *issued* credential/token so a verifier knows
  which list bit to read.

A revocation flow: allocate a list (:func:`~openvc.status.bitstring.new_bitstring`
or :func:`~openvc.status.token_status_list.new_status_list`), set the revoked
indices (``set_status_bit`` / ``set_status``), build + sign the artifact, serve it
at the URL the credentials point at, and re-issue it when a revocation changes.

This is the only :mod:`openvc.status` module that touches :mod:`openvc.proof` (to
sign/verify the token); the codecs and the check side stay pure stdlib.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from ..proof._jws import sign_compact, verify_compact
from ..proof.vc_jwt import SigningKey
from .bitstring import StatusListError, encode_bitstring
from .token_status_list import _check_bits, encode_status_list

_VC2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
BITSTRING_CREDENTIAL_TYPE = "BitstringStatusListCredential"
BITSTRING_SUBJECT_TYPE = "BitstringStatusList"
BITSTRING_ENTRY_TYPE = "BitstringStatusListEntry"
STATUS_LIST_JWT_TYP = "statuslist+jwt"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value: datetime | int) -> int:
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    return int(value)


# --------------------------------------------------------------------------- #
# W3C Bitstring Status List — the status-list credential + the entry
# --------------------------------------------------------------------------- #

def build_status_list_credential(
    *,
    id: str,
    issuer: str | dict[str, Any],
    bitstring: bytes | bytearray,
    status_purpose: str = "revocation",
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    subject_id: str | None = None,
    ttl: int | None = None,
    contexts: list[str] | None = None,
) -> dict[str, Any]:
    """Build an UNSIGNED W3C ``BitstringStatusListCredential`` wrapping *bitstring*.

    *id* is the URL a credential's ``statusListCredential`` points at; *bitstring*
    is the raw bits (from :func:`~openvc.status.bitstring.new_bitstring` +
    ``set_status_bit``). *status_purpose* must match the entries that reference this
    list. The result is a plain VC — **sign it** with any suite before publishing.
    The inputs are not mutated.
    """
    subject: dict[str, Any] = {
        "id": subject_id or f"{id}#list",
        "type": BITSTRING_SUBJECT_TYPE,
        "statusPurpose": status_purpose,
        "encodedList": encode_bitstring(bytes(bitstring)),
    }
    if ttl is not None:
        subject["ttl"] = ttl
    credential: dict[str, Any] = {
        "@context": list(contexts) if contexts else [_VC2_CONTEXT],
        "id": id,
        "type": ["VerifiableCredential", BITSTRING_CREDENTIAL_TYPE],
        "issuer": issuer,
        "credentialSubject": subject,
    }
    if valid_from is not None:
        credential["validFrom"] = _iso(valid_from)
    if valid_until is not None:
        credential["validUntil"] = _iso(valid_until)
    return credential


def build_status_list_entry(
    *,
    status_list_credential: str,
    index: int,
    status_purpose: str = "revocation",
    id: str | None = None,
) -> dict[str, Any]:
    """Build a ``BitstringStatusListEntry`` for a credential's ``credentialStatus``.

    Add the return value to each credential you issue; toggling the same *index* in
    the published list (:func:`build_status_list_credential`) then flips that
    credential's status. *status_purpose* must match the list's."""
    if index < 0:
        raise StatusListError(f"status index must be non-negative, got {index}")
    entry: dict[str, Any] = {
        "type": BITSTRING_ENTRY_TYPE,
        "statusPurpose": status_purpose,
        "statusListIndex": str(index),          # the spec encodes the index as a string
        "statusListCredential": status_list_credential,
    }
    if id is not None:
        entry["id"] = id
    return entry


# --------------------------------------------------------------------------- #
# IETF Token Status List — the status-list token + the referencing claim
# --------------------------------------------------------------------------- #

def build_status_list_token(
    *,
    signing_key: SigningKey,
    uri: str,
    status_list: bytes | bytearray,
    bits: int = 1,
    issued_at: datetime | int | None = None,
    expires: datetime | int | None = None,
    ttl: int | None = None,
    issuer: str | None = None,
) -> str:
    """Build and sign an IETF status-list token (``typ: statuslist+jwt``).

    *uri* (the ``sub`` claim, the list's own URL) is what a referenced token's
    ``status.status_list.uri`` points at; *status_list* is the packed multi-bit
    list (from :func:`~openvc.status.token_status_list.new_status_list` +
    ``set_status``). Signed via the allow-listed ``{ES256, EdDSA}`` path, so an
    HSM/Vault key works. *issued_at* / *expires* accept a datetime or epoch int."""
    _check_bits(bits)
    payload: dict[str, Any] = {
        "sub": uri,
        "iat": _epoch(issued_at) if issued_at is not None else int(time.time()),
        "status_list": {"bits": bits, "lst": encode_status_list(bytes(status_list))},
    }
    if issuer is not None:
        payload["iss"] = issuer
    if expires is not None:
        payload["exp"] = _epoch(expires)
    if ttl is not None:
        payload["ttl"] = ttl
    header = {"typ": STATUS_LIST_JWT_TYP, "alg": signing_key.alg, "kid": signing_key.kid}
    return sign_compact(header, payload, signing_key=signing_key)


def verify_status_list_token(
    token: str,
    *,
    public_key_jwk: dict[str, Any],
    expected_uri: str | None = None,
    leeway_s: int = 60,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a status-list token and return its claims.

    Allow-lists the algorithm, requires ``typ: statuslist+jwt``, verifies the
    signature, checks ``exp`` (within *leeway_s*), and — when *expected_uri* is
    given — that ``sub`` equals the URL it was fetched from (the IETF anti-swap
    check). The returned dict carries the ``status_list`` member, so it can be
    handed straight to :func:`~openvc.status.token_status_list.check_token_status`
    as the resolver's result."""
    header, claims = verify_compact(token, public_key_jwk=public_key_jwk)
    if header.get("typ") != STATUS_LIST_JWT_TYP:
        raise StatusListError(
            f"unexpected token typ {header.get('typ')!r}, want {STATUS_LIST_JWT_TYP!r}")
    if expected_uri is not None and claims.get("sub") != expected_uri:
        raise StatusListError(
            f"status list token sub {claims.get('sub')!r} != expected {expected_uri!r}")
    exp = claims.get("exp")
    if exp is not None:
        # exp is a NumericDate (RFC 7519); a present-but-non-numeric exp fails
        # CLOSED — skipping it would let a stale/superseded list be accepted (the
        # same fail-open bug openvc.proof._verify_common is written to avoid).
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise StatusListError(
                f"status list token exp must be a numeric timestamp, got {exp!r}")
        instant = _epoch(now) if now is not None else int(time.time())
        if instant - max(0, leeway_s) > exp:
            raise StatusListError("status list token has expired")
    return claims


def build_token_status_reference(*, uri: str, index: int) -> dict[str, Any]:
    """Build the ``status`` claim a referenced token carries to point at an IETF
    status-list token — merge it into the token's claims when you issue it."""
    if index < 0:
        raise StatusListError(f"status index must be non-negative, got {index}")
    return {"status": {"status_list": {"idx": index, "uri": uri}}}
