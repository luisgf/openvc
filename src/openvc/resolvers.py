"""
openvc.resolvers — blessed, SSRF-guarded default resolvers for the status and
schema fetch paths.

:func:`~openvc.verify.verify_credential`'s ``resolve_status_list``,
``resolve_status_list_token`` and ``resolve_credential_schema`` are **caller-injected**:
the transport, the SSRF policy for each issuer-named host, and — for status — the
proof verification of the fetched list are the caller's concern, so
``openvc.fetch``'s guard protects these URLs only if you pass a guarded fetch. That
makes the secure path the *opt-in* path.

These factories are the safe drop-in that makes the secure path the *easy* path:
they fetch through the SSRF-guarded https fetch (``openvc.fetch``: https-only,
private/loopback/link-local blocked, redirects refused, connection pinned to the
validated IP) and — for status — **verify** the fetched status list through the
pipeline before trusting it. Pass one of these to ``verify_credential``; a custom
resolver deliberately opts out of the guard.

    from openvc import verify_credential
    from openvc.resolvers import (default_status_list_resolver,
                                  default_credential_schema_resolver)

    verify_credential(
        cred, resolver=reg,
        resolve_status_list=default_status_list_resolver(resolver=reg),
        resolve_credential_schema=default_credential_schema_resolver())
"""
from __future__ import annotations

import json
from typing import Any

from .fetch import https_bytes_fetch, https_text_fetch
from .schema import ResolveCredentialSchema
from .status import ResolveStatusList, ResolveStatusListToken
from .type_metadata import ResolveTypeMetadata


def default_credential_schema_resolver(
    *, fetch: Any = https_bytes_fetch,
) -> ResolveCredentialSchema:
    """A ``resolve_credential_schema`` that fetches the raw schema bytes over the
    SSRF-guarded https fetch. Returning bytes lets the pipeline verify a
    ``credentialSchema.digestSRI`` over the exact response before parsing."""
    def resolve(url: str) -> bytes:
        return fetch(url)
    return resolve


def default_type_metadata_resolver(
    *, fetch: Any = https_bytes_fetch,
) -> ResolveTypeMetadata:
    """A ``resolve`` for :func:`openvc.type_metadata.validate_type_metadata` that
    fetches the raw Type Metadata bytes from a ``vct`` / ``extends`` URL over the
    SSRF-guarded https fetch. Returning the exact bytes lets ``vct#integrity`` /
    ``extends#integrity`` be verified over the response before parsing."""
    def resolve(url: str) -> bytes:
        return fetch(url)
    return resolve


def default_status_list_resolver(
    *, resolver: Any = None, jwt_vc_issuer_fetch: Any = None,
    leeway_s: int = 60, extra_contexts: Any = None, fetch: Any = https_text_fetch,
) -> ResolveStatusList:
    """A ``resolve_status_list`` (W3C Bitstring) that fetches the status-list
    credential over the SSRF-guarded https fetch and **verifies** it through the
    pipeline before returning it — a fetched-but-unverified status list would let a
    forged one clear revocation. Status-of-status recursion is turned off
    (``require_status=False``); *resolver* resolves the status issuer's key."""
    def resolve(url: str) -> dict:
        from .verify import VerificationPolicy, verify_credential
        credential = _as_credential(fetch(url))
        result = verify_credential(
            credential, resolver=resolver, jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            policy=VerificationPolicy(require_status=False, leeway_s=leeway_s),
            extra_contexts=extra_contexts)
        return result.credential
    return resolve


def default_status_list_token_resolver(
    *, resolver: Any = None, jwt_vc_issuer_fetch: Any = None,
    leeway_s: int = 60, fetch: Any = https_text_fetch,
) -> ResolveStatusListToken:
    """A ``resolve_status_list_token`` (IETF) that fetches the ``statuslist+jwt``
    token over the SSRF-guarded https fetch, resolves the issuer key, verifies the
    token (typ + signature + ``exp`` + ``sub`` == the fetched URI, the IETF
    anti-swap check), and returns its claims."""
    def resolve(uri: str) -> dict:
        from .proof._jws import parse_compact
        from .status import StatusListError, verify_status_list_token
        from .verify import _resolve_jose_key, default_resolver
        token = fetch(uri).strip()
        header, payload, _, _ = parse_compact(token)
        iss, kid = payload.get("iss"), header.get("kid")
        if not isinstance(iss, str) or not iss:
            raise StatusListError(
                "status list token has no string `iss` to resolve its key")
        reg = resolver if resolver is not None else default_resolver()
        jwk = _resolve_jose_key(reg, iss, kid, jwt_vc_issuer_fetch)
        return verify_status_list_token(
            token, public_key_jwk=jwk, expected_uri=uri, leeway_s=leeway_s)
    return resolve


def _as_credential(raw: str) -> Any:
    """A fetched status-list credential is JSON (Data Integrity) or a compact JWS
    (VC-JWT): return a dict for the former, the JWS string for the latter."""
    text = raw.strip()
    try:
        obj = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return text
    return obj if isinstance(obj, dict) else text


__all__ = [
    "default_credential_schema_resolver",
    "default_status_list_resolver",
    "default_status_list_token_resolver",
    "default_type_metadata_resolver",
]
