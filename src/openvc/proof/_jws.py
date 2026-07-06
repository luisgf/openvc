"""
openvc.proof._jws — generic compact JWS (JWS Compact Serialization): assembly,
parsing, and signature verification, shared by the JOSE-secured formats.

``VcJwtProofSuite.sign`` was the only place that assembled a compact JWS. This
lifts that assembly out so a **non-VC** token — notably the IETF status-list token
(``typ: statuslist+jwt``, see :mod:`openvc.status.issue`) — signs through the same
allow-listed ``{ES256, EdDSA}`` :class:`~openvc.proof.vc_jwt.SigningKey` path,
without duplicating the base64url/JSON/signature dance or widening the algorithm
policy. Header and payload are serialised with compact separators and signed
byte-for-byte identically to the previous inline code, so existing tokens are
unchanged.

Errors are reused from :mod:`openvc.proof.vc_jwt` so the whole JOSE family shares
one exception hierarchy under ``ProofError``.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from .errors import MalformedToken, SignatureInvalid, UnsupportedAlgorithm
from .vc_jwt import ALLOWED_ALGS, SigningKey


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def sign_compact(
    header: dict[str, Any], payload: dict[str, Any], *, signing_key: SigningKey
) -> str:
    """Assemble a signed compact JWS ``b64url(header).b64url(payload).b64url(sig)``.

    The algorithm is taken from the key and allow-listed BEFORE signing (the same
    ``{ES256, EdDSA}`` policy a verifier enforces); the raw signature comes from
    the :class:`SigningKey` backend, so an HSM/Vault key never leaves its boundary.
    """
    if signing_key.alg not in ALLOWED_ALGS:
        raise UnsupportedAlgorithm(f"key alg {signing_key.alg!r} not permitted")
    signing_input = f"{b64url_encode(_json_bytes(header))}.{b64url_encode(_json_bytes(payload))}"
    signature = signing_key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{b64url_encode(signature)}"


def parse_compact(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a compact JWS into ``(header, payload, signing_input, signature)``
    WITHOUT verifying. Untrusted — use only to read the header/claims before (or in
    order to) verify."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise MalformedToken("not a valid compact JWS (need 3 base64url JSON parts)") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise MalformedToken("JWS header and payload must be JSON objects")
    return header, payload, f"{header_b64}.{payload_b64}".encode("ascii"), signature


def verify_compact(
    token: str,
    *,
    public_key_jwk: dict[str, Any],
    allowed_algs: frozenset[str] = ALLOWED_ALGS,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse, allow-list the algorithm BEFORE any crypto, and verify the signature
    against *public_key_jwk*. Returns ``(header, payload)``. Temporal, ``typ`` and
    claim policy are the caller's concern — this is the signature layer only."""
    header, payload, signing_input, signature = parse_compact(token)
    alg = header.get("alg")
    if alg not in allowed_algs:
        raise UnsupportedAlgorithm(f"algorithm {alg!r} is not permitted")
    from ..keys import KeyBackendError, verify_signature
    try:
        ok = verify_signature(
            alg=alg, public_jwk=public_key_jwk,
            signing_input=signing_input, signature=signature)
    except KeyBackendError as exc:
        raise SignatureInvalid(f"could not verify signature: {exc}") from exc
    if not ok:
        raise SignatureInvalid("signature verification failed")
    return header, payload
