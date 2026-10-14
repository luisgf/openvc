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
  shared JOSE path (allow-listed ``{ES256, ES384, EdDSA, Ed25519}``).
* :func:`build_status_list_entry` / :func:`build_token_status_reference` — the tiny
  pointer an issuer embeds in each *issued* credential/token so a verifier knows
  which list bit to read.

A revocation flow: allocate a list (:func:`~openvc.status.bitstring.new_bitstring`
or :func:`~openvc.status.token_status_list.new_status_list`), set the revoked
indices (``set_status_bit`` / ``set_status``), build + sign the artifact, serve it
at the URL the credentials point at, and re-issue it when a revocation changes.

The builders hold the pointer and the list to the rules the verifier applies, so openvc
never mints one that its own check side then refuses: an index follows
:func:`~openvc.status._index.status_index` (an ``int``, never a ``bool`` or ``float``,
below ``MAX_STATUS_INDEX``), the pointer strings are non-empty strings, and a list is
bytes-like and may not exceed the 16 MiB the verifier inflates. Anything else is a
:class:`~openvc.status.bitstring.StatusListError`, raised at build time. The time inputs
(*issued_at*, *expires*, *valid_from*) and *ttl* are not covered by this.

This is the only :mod:`openvc.status` module that touches :mod:`openvc.proof` (to
sign/verify the token); the codecs and the check side stay pure stdlib.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from ..proof._jws import sign_compact, verify_compact
from ..proof._verify_common import check_jwt_temporal, is_numeric_date, utc_epoch
from ..proof.errors import ClaimsInvalid
from ..proof.vc_jwt import SigningKey
from ._decompress import MAX_DECOMPRESSED_BYTES
from ._index import brief, status_index
from .bitstring import StatusListError, encode_bitstring
from .token_status_list import _check_bits, encode_status_list

_VC2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
BITSTRING_CREDENTIAL_TYPE = "BitstringStatusListCredential"
BITSTRING_SUBJECT_TYPE = "BitstringStatusList"
BITSTRING_ENTRY_TYPE = "BitstringStatusListEntry"
STATUS_LIST_JWT_TYP = "statuslist+jwt"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(value: Any, *, field: str) -> str:
    """*value* if it is a non-empty ``str``, else a typed error: the verifier reads these
    fields as strings, and an empty one names nothing."""
    if not isinstance(value, str) or not value:
        raise StatusListError(f"{field} must be a non-empty string, got {brief(value)}")
    return value


def _packed(value: Any, *, field: str) -> bytes:
    """The list bytes of *value*, refused when it is not bytes-like (``bytes``,
    ``bytearray``, ``memoryview``, ``array.array``...) or longer than the verifier
    inflates (``MAX_DECOMPRESSED_BYTES``) — checked before compressing it, so a list
    that cannot be decoded is never even built."""
    try:
        # memoryview refuses an int, a str, None and a list; ``bytes(int)`` would be a
        # silent zeroed list. It counts bytes, where ``len()`` of an array counts items.
        view = memoryview(value)
    except (TypeError, ValueError):                  # ValueError: a released memoryview
        raise StatusListError(f"{field} must be bytes-like, got {brief(value)}") from None
    if view.nbytes > MAX_DECOMPRESSED_BYTES:
        raise StatusListError(
            f"{field} is {view.nbytes} bytes, past the {MAX_DECOMPRESSED_BYTES} the "
            f"verifier decodes: openvc would refuse to read the list back")
    return bytes(view)


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
    bitstring: bytes | bytearray | memoryview,
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

    Raises :class:`~openvc.status.bitstring.StatusListError` for an *id* or
    *status_purpose* that is not a non-empty string, and for a *bitstring* that is not
    bytes-like (``bytes``, ``bytearray``, ``memoryview``...) or is longer than the
    16 MiB the verifier inflates.
    """
    _text(id, field="status list credential id")
    _text(status_purpose, field="statusPurpose")
    raw_bits = _packed(bitstring, field="bitstring")
    subject: dict[str, Any] = {
        "id": subject_id or f"{id}#list",
        "type": BITSTRING_SUBJECT_TYPE,
        "statusPurpose": status_purpose,
        "encodedList": encode_bitstring(raw_bits),
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
    credential's status. *status_purpose* must match the list's.

    *index* is an ``int`` below :data:`~openvc.status._index.MAX_STATUS_INDEX` — the
    verifier's own rule, so it reads back exactly what you wrote; the entry carries it
    as the base-10 string the spec asks for. A ``bool``, a ``float`` (``NaN``
    included), a string, a negative or an oversized index, or a *status_list_credential*
    / *status_purpose* that is not a non-empty string, raises
    :class:`~openvc.status.bitstring.StatusListError`."""
    index = status_index(index, field="statusListIndex", allow_string=False)
    _text(status_list_credential, field="statusListCredential")
    _text(status_purpose, field="statusPurpose")
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
    status_list: bytes | bytearray | memoryview,
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
    ``set_status``). Signed via the allow-listed ``{ES256, ES384, EdDSA, Ed25519}`` path, so an
    HSM/Vault key works. *issued_at* / *expires* accept a datetime or epoch int.

    Raises :class:`~openvc.status.bitstring.StatusListError` for a *uri* that is not a
    non-empty string, a bad *bits*, and a *status_list* that is not bytes-like or is
    longer than the 16 MiB the verifier inflates."""
    _text(uri, field="status list token uri")
    _check_bits(bits)
    packed = _packed(status_list, field="status_list")
    payload: dict[str, Any] = {
        "sub": uri,
        "iat": _epoch(issued_at) if issued_at is not None else int(time.time()),
        "status_list": {"bits": bits, "lst": encode_status_list(packed)},
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
    signature, checks ``exp`` / ``nbf`` / ``iat`` (finite numbers when present, ``null``
    included; within *leeway_s* of *now*), and — when *expected_uri* is
    given — that ``sub`` equals the URL it was fetched from (the IETF anti-swap
    check). The returned dict carries the ``status_list`` member, so it can be
    handed straight to :func:`~openvc.status.token_status_list.check_token_status`
    as the resolver's result."""
    header, claims = verify_compact(token, public_key_jwk=public_key_jwk)
    if header.get("typ") != STATUS_LIST_JWT_TYP:
        raise StatusListError(
            f"unexpected token typ {brief(header.get('typ'))}, want {STATUS_LIST_JWT_TYP!r}")
    if expected_uri is not None and claims.get("sub") != expected_uri:
        raise StatusListError(
            f"status list token sub {brief(claims.get('sub'))} != expected {expected_uri!r}")
    # The shared JOSE rule (ADR-0008): a present exp/nbf/iat, null included, must be a
    # finite JSON number; NaN / Infinity / 1e400 would make every comparison False, so
    # the list would never go stale. exp, nbf and a future iat are all judged at one
    # instant: *now* when pinned, else the wall clock (the resolvers never pin it). A
    # pin earlier than the list's iat/nbf therefore rejects it: the list did not exist
    # at that instant.
    for name in ("exp", "nbf", "iat"):        # shape first, naming what came instead
        if name in claims and not is_numeric_date(claims[name]):
            raise StatusListError(
                f"status list token {name} must be a finite numeric timestamp, "
                f"got {brief(claims[name])}")
    if now is None:
        instant = None
    elif isinstance(now, int) and not isinstance(now, bool):
        instant = now                             # epoch seconds, as _epoch accepted
    else:                                         # a datetime; anything else is typed
        instant = utc_epoch(now, error=StatusListError)
    try:
        check_jwt_temporal(claims, leeway_s=max(0, leeway_s),
                           subject="status list token", now=instant)
    except ClaimsInvalid as exc:
        raise StatusListError(str(exc)) from exc
    return claims


def build_token_status_reference(*, uri: str, index: int) -> dict[str, Any]:
    """Build the ``status`` claim a referenced token carries to point at an IETF
    status-list token — merge it into the token's claims when you issue it.

    *index* follows the same rule as :func:`build_status_list_entry`, and the IETF
    draft makes it a JSON integer, so a string is refused too; *uri* must be a non-empty
    string. :class:`~openvc.status.bitstring.StatusListError` otherwise."""
    idx = status_index(index, field="status_list idx", allow_string=False)
    _text(uri, field="status_list uri")
    return {"status": {"status_list": {"idx": idx, "uri": uri}}}


__all__ = [
    "STATUS_LIST_JWT_TYP",
    "build_status_list_credential",
    "build_status_list_entry",
    "build_status_list_token",
    "build_token_status_reference",
    "verify_status_list_token",
]
