"""
openvc.aio — an additive **async** verification surface over the sync pipeline.

:func:`verify_credential_async` mirrors :func:`openvc.verify.verify_credential`
exactly — same formats, same policy, same fail-closed guarantees — but ``await``\\s
its I/O (DID resolution, ``jwt-vc-issuer`` discovery, status-list and
``credentialSchema`` fetches) instead of blocking. It reuses **every** pure/CPU
helper of the sync path unchanged (the proof suites, the status/schema codecs, the
issuer binding and type checks); only the sequencing around the I/O boundaries is
re-expressed with ``await``. There is no second implementation of any signature
check to drift — see ``docs/adr/ADR-0002-async-verification.md``.

Injection mirrors the sync path with async counterparts: *resolver* is an
:class:`~openvc.did.base.AsyncDidResolver`; ``resolve_status_list`` /
``resolve_status_list_token`` / ``resolve_credential_schema`` / ``jwt_vc_issuer_fetch``
each return an awaitable. The caller supplies the transport — an
``httpx.AsyncClient``-backed fetch, or the batteries-included
:func:`openvc.fetch.https_json_fetch_async` (the exact same SSRF/DNS-rebind guard
as the sync fetch, run off the event loop). :func:`default_async_resolver` wires
the offline did:key / did:jwk resolvers (via :func:`~openvc.did.base.as_async_resolver`)
and the SSRF-guarded async did:web resolver.

:func:`verify_many_async` verifies a batch **concurrently** (``asyncio.gather``),
each item independently fail-closed — the fix for a presentation cascade that would
otherwise serialise N blocking fetches.

**Data Integrity note:** the embedded-proof suites resolve the proof's
``verificationMethod`` synchronously; the async path resolves that DID *first*
(awaiting the injected resolver) and hands the suite a one-shot in-memory resolver,
so the suite's own resolution does no I/O. The canonicalisation + signature check
then run inline on the event loop (bounded CPU).
"""
from __future__ import annotations

import asyncio
from typing import Any, Sequence, Union

from .did.base import (
    AsyncDidResolverRegistry,
    DidResolutionError,
    UnsupportedDidMethod,
    as_async_resolver,
)
from .errors import OpenvcError
from .observability import logger, span
from .schema import SchemaUnavailable, validate_credential_schema_async
from .status import (
    CredentialRevoked,
    CredentialSuspended,
    StatusResult,
    TokenStatusResult,
    check_credential_status_async,
    check_token_status_async,
    parse_status_entries,
    parse_token_status_ref,
)
from .verify import (
    FORMAT_DI_ECDSA_JCS,
    FORMAT_DI_ECDSA_RDFC,
    FORMAT_DI_ECDSA_SD,
    FORMAT_DI_EDDSA_JCS,
    FORMAT_ENVELOPED,
    FORMAT_SD_JWT_VC,
    FORMAT_VC_JWT,
    BatchResult,
    KeyResolutionFailed,
    StatusUnavailable,
    UnknownCredentialFormat,
    VerificationPolicy,
    VerificationResult,
    _as_str,
    _bind_issuer_to_verification_method,
    _bytes_to_credential,
    _check_types,
    _fail_closed,
    _unwrap_enveloped,
    detect_format,
)


# --------------------------------------------------------------------------- #
# Default async resolver
# --------------------------------------------------------------------------- #

def default_async_resolver() -> AsyncDidResolverRegistry:
    """The async counterpart of :func:`openvc.verify.default_resolver`: the offline
    ``did:key`` / ``did:jwk`` resolvers (adapted via :func:`as_async_resolver`) plus
    the SSRF-guarded async ``did:web`` resolver."""
    from .did.did_jwk import DidJwkResolver
    from .did.did_key import DidKeyResolver
    from .fetch import default_async_did_web_resolver
    return AsyncDidResolverRegistry([
        as_async_resolver(DidKeyResolver()),
        as_async_resolver(DidJwkResolver()),
        default_async_did_web_resolver(),
    ])


# --------------------------------------------------------------------------- #
# The pipeline
# --------------------------------------------------------------------------- #

async def verify_credential_async(
    credential: Any,
    *,
    policy: VerificationPolicy | None = None,
    resolver: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    resolve_credential_schema: Any = None,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    extra_contexts: Any = None,
    _depth: int = 0,
) -> VerificationResult:
    """Async :func:`openvc.verify.verify_credential`. Every keyword means what it does
    there, with async counterparts for the injected I/O: *resolver* is an
    :class:`~openvc.did.base.AsyncDidResolver` (default :func:`default_async_resolver`),
    and the status/schema/issuer fetches return awaitables. Same formats, same policy,
    same fail-closed behaviour and same :class:`VerificationResult`."""
    policy = policy or VerificationPolicy()
    resolver = resolver if resolver is not None else default_async_resolver()

    fmt = detect_format(credential)
    logger.debug("verify_async: format=%s", fmt)
    with span("openvc.verify_credential_async", format=fmt):
        try:
            result = await _verify_by_format_async(
                credential, fmt, policy, resolver, resolve_status_list,
                resolve_status_list_token, resolve_credential_schema,
                jwt_vc_issuer_fetch, x5c_trust_anchors, extra_contexts, _depth)
        except OpenvcError as exc:
            logger.info("verify_async failed: format=%s error=%s", fmt, type(exc).__name__)
            raise
        logger.debug("verify_async ok: format=%s issuer=%s", result.format, result.issuer)
    return result


async def _verify_by_format_async(
    credential: Any, fmt: str, policy: VerificationPolicy, resolver: Any,
    resolve_status_list: Any, resolve_status_list_token: Any,
    resolve_credential_schema: Any, jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any,
    extra_contexts: Any, _depth: int,
) -> VerificationResult:
    if fmt == FORMAT_ENVELOPED:
        if _depth >= 2:
            raise UnknownCredentialFormat("enveloped credential nested too deeply")
        return await verify_credential_async(
            _unwrap_enveloped(credential), policy=policy, resolver=resolver,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            resolve_credential_schema=resolve_credential_schema,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            extra_contexts=extra_contexts, _depth=_depth + 1)

    verify_inner = _make_schema_verifier_async(
        policy, resolver, resolve_status_list, resolve_status_list_token,
        jwt_vc_issuer_fetch, x5c_trust_anchors, extra_contexts, _depth)

    if fmt == FORMAT_VC_JWT:
        return await _verify_vc_jwt_async(
            credential, policy, resolver, resolve_status_list,
            resolve_status_list_token, resolve_credential_schema,
            jwt_vc_issuer_fetch, x5c_trust_anchors, verify_inner)
    if fmt == FORMAT_SD_JWT_VC:
        return await _verify_sd_jwt_async(
            credential, policy, resolver, resolve_status_list,
            resolve_status_list_token, resolve_credential_schema,
            jwt_vc_issuer_fetch, x5c_trust_anchors, verify_inner)
    return await _verify_data_integrity_async(
        credential, fmt, policy, resolver, resolve_status_list,
        resolve_status_list_token, resolve_credential_schema, extra_contexts,
        verify_inner)


async def verify_many_async(
    credentials: Sequence[Any],
    *,
    policy: VerificationPolicy | None = None,
    resolver: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    resolve_credential_schema: Any = None,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    extra_contexts: Any = None,
) -> list[BatchResult]:
    """Verify many credentials **concurrently** (``asyncio.gather``), each independently
    fail-closed: one failure becomes that item's ``error`` and never aborts the others.
    Returns one :class:`BatchResult` per input, in input order. Unlike the sync
    :func:`openvc.verify.verify_many`, this does not de-duplicate shared resolutions
    across credentials (that cache is not concurrency-safe — ADR-0002 D4); overlapping
    the I/O is the win here."""
    resolver = resolver if resolver is not None else default_async_resolver()

    async def _one(index: int, credential: Any) -> BatchResult:
        try:
            result = await verify_credential_async(
                credential, policy=policy, resolver=resolver,
                resolve_status_list=resolve_status_list,
                resolve_status_list_token=resolve_status_list_token,
                resolve_credential_schema=resolve_credential_schema,
                jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
                x5c_trust_anchors=x5c_trust_anchors, extra_contexts=extra_contexts)
            return BatchResult(index=index, result=result)
        except OpenvcError as exc:          # per-credential fail-closed
            return BatchResult(index=index, error=exc)

    with span("openvc.verify_many_async", count=len(credentials)):
        results = await asyncio.gather(
            *(_one(i, c) for i, c in enumerate(credentials)))
    ok = sum(1 for r in results if r.ok)
    logger.debug("verify_many_async: %d credentials, %d ok", len(results), ok)
    return list(results)


# -- per-format handlers ---------------------------------------------------- #

async def _verify_vc_jwt_async(
    token: str, policy: VerificationPolicy, resolver: Any, resolve_status_list: Any,
    resolve_status_list_token: Any, resolve_credential_schema: Any,
    jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any, verify_inner: Any,
) -> VerificationResult:
    from .proof.vc_jwt import VcJwtProofSuite

    suite = VcJwtProofSuite(leeway_s=policy.leeway_s)
    iss, kid = suite.peek_issuer(token)
    jwk = await _resolve_jose_key_with_x5c_async(
        token, iss, kid, sd_jwt=False, resolver=resolver,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors, now=policy.now)
    verified = suite.verify(token, public_key_jwk=jwk, audience=policy.audience)
    _check_types(verified.credential, policy.expected_types)
    status = await _check_status_async(verified.credential, verified.claims, policy,
                                       resolve_status_list, resolve_status_list_token)
    schema = await _check_schema_async(verified.credential, policy,
                                       resolve_credential_schema, verify_inner)
    return VerificationResult(
        format=FORMAT_VC_JWT, credential=verified.credential, claims=verified.claims,
        issuer=verified.issuer, subject=verified.subject, status=status,
        schema=schema, raw=verified)


async def _verify_sd_jwt_async(
    sd_jwt: str, policy: VerificationPolicy, resolver: Any, resolve_status_list: Any,
    resolve_status_list_token: Any, resolve_credential_schema: Any,
    jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any, verify_inner: Any,
) -> VerificationResult:
    from .proof.sd_jwt import SdJwtVcProofSuite

    suite = SdJwtVcProofSuite(leeway_s=policy.leeway_s)
    iss, kid = suite.peek_issuer(sd_jwt)
    jwk = await _resolve_jose_key_with_x5c_async(
        sd_jwt, iss, kid, sd_jwt=True, resolver=resolver,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors, now=policy.now)
    verified = suite.verify(
        sd_jwt, public_key_jwk=jwk, audience=policy.audience, nonce=policy.nonce,
        require_key_binding=policy.require_key_binding, expected_vct=policy.expected_vct)
    status = await _check_status_async(verified.claims, verified.claims, policy,
                                       resolve_status_list, resolve_status_list_token)
    schema = await _check_schema_async(verified.claims, policy,
                                       resolve_credential_schema, verify_inner)
    return VerificationResult(
        format=FORMAT_SD_JWT_VC, credential=verified.claims, claims=verified.claims,
        issuer=verified.issuer, subject=_as_str(verified.claims.get("sub")),
        key_bound=verified.key_bound, status=status, schema=schema, raw=verified)


async def _verify_data_integrity_async(
    doc: dict[str, Any], fmt: str, policy: VerificationPolicy, resolver: Any,
    resolve_status_list: Any, resolve_status_list_token: Any,
    resolve_credential_schema: Any, extra_contexts: Any, verify_inner: Any,
) -> VerificationResult:
    if fmt == FORMAT_DI_ECDSA_SD:
        from .proof.ecdsa_sd import EcdsaSdProofSuite
        suite: Any = EcdsaSdProofSuite(leeway_s=policy.leeway_s)
    elif fmt == FORMAT_DI_EDDSA_JCS:
        from .proof.di_jcs import EddsaJcsProofSuite
        suite = EddsaJcsProofSuite(leeway_s=policy.leeway_s)
    elif fmt == FORMAT_DI_ECDSA_JCS:
        from .proof.di_jcs import EcdsaJcsProofSuite
        suite = EcdsaJcsProofSuite(leeway_s=policy.leeway_s)
    elif fmt == FORMAT_DI_ECDSA_RDFC:
        from .proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
        suite = EcdsaRdfcProofSuite(leeway_s=policy.leeway_s)
    else:
        from .proof.data_integrity import DataIntegrityProofSuite
        suite = DataIntegrityProofSuite(leeway_s=policy.leeway_s)

    # Resolve the proof's verificationMethod DID up front (async); the suite then
    # verifies synchronously against a one-shot in-memory resolver — no I/O inside.
    sync_resolver = await _preresolved_di_resolver(doc, resolver)
    if fmt in (FORMAT_DI_EDDSA_JCS, FORMAT_DI_ECDSA_JCS):
        verified = suite.verify(
            doc, resolver=sync_resolver, expected_proof_purpose=policy.proof_purpose,
            now=policy.now)
    else:
        verified = suite.verify(
            doc, resolver=sync_resolver, expected_proof_purpose=policy.proof_purpose,
            now=policy.now, extra_contexts=extra_contexts)
    _bind_issuer_to_verification_method(verified)
    _check_types(verified.credential, policy.expected_types)
    status = await _check_status_async(verified.credential, verified.credential, policy,
                                       resolve_status_list, resolve_status_list_token)
    schema = await _check_schema_async(verified.credential, policy,
                                       resolve_credential_schema, verify_inner)
    return VerificationResult(
        format=fmt, credential=verified.credential, issuer=verified.issuer,
        subject=verified.subject, status=status, schema=schema, raw=verified)


# -- async key resolution --------------------------------------------------- #

async def _resolve_jose_key_with_x5c_async(
    token: str, iss: str, kid: str | None, *, sd_jwt: bool, resolver: Any,
    jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any, now: Any,
) -> dict[str, Any]:
    """Async counterpart of ``_resolve_jose_key_with_x5c``. The x5c branch is pure
    CPU (chain validation, no I/O) and runs inline; the issuer/DID branch awaits."""
    if x5c_trust_anchors is not None:
        from .proof._jws import parse_compact
        jws = token.split("~", 1)[0] if sd_jwt else token
        header, _, _, _ = parse_compact(jws)
        x5c = header.get("x5c")
        if x5c:
            from .x5c import X5cError, resolve_x5c_key
            try:
                return resolve_x5c_key(x5c, iss, trust_anchors=x5c_trust_anchors, now=now)
            except X5cError as exc:
                raise KeyResolutionFailed(
                    f"x5c key resolution failed for issuer {iss!r}: {exc}") from exc
    return await _resolve_jose_key_async(resolver, iss, kid, jwt_vc_issuer_fetch)


async def _resolve_jose_key_async(
    resolver: Any, iss: str, kid: str | None, jwt_vc_issuer_fetch: Any = None,
) -> dict[str, Any]:
    """Async counterpart of ``openvc.verify._resolve_jose_key``: an https issuer is
    resolved via /.well-known/jwt-vc-issuer (awaiting *jwt_vc_issuer_fetch*), else the
    key comes from the async DID *resolver*."""
    from .did.base import DidError

    if iss.startswith("https://"):
        if jwt_vc_issuer_fetch is None:
            raise KeyResolutionFailed(
                f"issuer {iss!r} is an https URL; pass an async jwt_vc_issuer_fetch "
                "(e.g. openvc.fetch.https_json_fetch_async) to resolve its key")
        from .jwt_vc_issuer import JwtVcIssuerError, resolve_jwt_vc_issuer_key_async
        try:
            return await resolve_jwt_vc_issuer_key_async(iss, kid, fetch=jwt_vc_issuer_fetch)
        except (JwtVcIssuerError, DidError) as exc:
            raise KeyResolutionFailed(
                f"could not resolve issuer key for {iss!r}: {exc}") from exc

    try:
        doc = await resolver.resolve(iss)
    except DidError as exc:
        raise KeyResolutionFailed(
            f"could not resolve issuer DID {iss!r}: {exc}") from exc
    vm = doc.key_by_kid(kid)
    if vm is None:
        raise KeyResolutionFailed(
            f"no verification method for kid {kid!r} in DID {iss!r}")
    return vm.public_key_jwk


class _OneShotResolver:
    """A sync resolver holding one already-resolved DID document — lets a (sync)
    Data Integrity suite pick the verification key without doing any I/O."""
    def __init__(self, did: str, doc: Any) -> None:
        self._did = did
        self._doc = doc

    def supports(self, did: str) -> bool:
        return did == self._did

    def resolve(self, did: str) -> Any:
        if did != self._did:
            raise DidResolutionError(f"unknown DID {did!r}")
        return self._doc


async def _preresolved_di_resolver(doc: dict[str, Any], resolver: Any) -> Any:
    """Await the async *resolver* for the DI proof's ``verificationMethod`` DID and
    return a sync :class:`_OneShotResolver` the suite can use with no further I/O.

    Mirrors the resolver handling in ``resolve_verification_key``: when the resolver
    does not support the DID (or raises :class:`UnsupportedDidMethod`) we return
    ``None`` so the suite falls back to offline ``did:key``; a
    :class:`DidResolutionError` becomes a :class:`KeyResolutionFailed`."""
    raw_proof = doc.get("proof")
    proof = raw_proof if isinstance(raw_proof, dict) else {}
    vm = proof.get("verificationMethod")
    if not isinstance(vm, str) or not vm or resolver is None:
        return None                         # let the suite raise / fall back to did:key
    did = vm.split("#", 1)[0]
    supports = getattr(resolver, "supports", None)
    if supports is not None and not supports(did):
        return None                         # unsupported -> suite falls back to did:key
    try:
        did_doc = await resolver.resolve(did)
    except UnsupportedDidMethod:
        return None
    except DidResolutionError as exc:
        raise KeyResolutionFailed(f"could not resolve {did!r}: {exc}") from exc
    return _OneShotResolver(did, did_doc)


# -- async status / schema (mirror openvc.verify._check_status/_check_schema) - #

async def _check_status_async(
    w3c_source: dict[str, Any],
    ietf_source: dict[str, Any] | None,
    policy: VerificationPolicy,
    resolve_status_list: Any,
    resolve_status_list_token: Any,
) -> "Union[StatusResult, TokenStatusResult, None]":
    """Async twin of ``openvc.verify._check_status`` — identical gating (revoked /
    suspended raise; a declared-but-unresolvable status fails closed), awaiting the
    async status checks."""
    result: Union[StatusResult, TokenStatusResult, None] = None

    entries = parse_status_entries(w3c_source)
    if entries:
        if resolve_status_list is None:
            _fail_closed(policy, "credentialStatus", "resolve_status_list")
        else:
            w3c = await check_credential_status_async(
                w3c_source, resolve_status_list=resolve_status_list)
            if w3c.revoked:
                raise CredentialRevoked(f"credential {w3c_source.get('id')!r} is revoked")
            if w3c.suspended:
                raise CredentialSuspended(f"credential {w3c_source.get('id')!r} is suspended")
            result = w3c
    elif w3c_source.get("credentialStatus") and policy.require_status:
        raise StatusUnavailable(
            "credential declares a credentialStatus of an unrecognised type "
            "(set policy.require_status=False to skip)")

    if ietf_source is not None:
        ref = parse_token_status_ref(ietf_source)
        if ref is not None:
            if resolve_status_list_token is None:
                _fail_closed(policy, "status reference", "resolve_status_list_token")
            else:
                ietf = await check_token_status_async(
                    ietf_source, resolve_status_list_token=resolve_status_list_token)
                if ietf is not None:
                    if ietf.revoked:
                        raise CredentialRevoked("token is revoked")
                    if ietf.suspended:
                        raise CredentialSuspended("token is suspended")
                    result = result if result is not None else ietf
        elif ietf_source.get("status") is not None and policy.require_status:
            raise StatusUnavailable(
                "credential declares a status of an unrecognised shape "
                "(set policy.require_status=False to skip)")

    return result


async def _check_schema_async(
    credential: dict[str, Any],
    policy: VerificationPolicy,
    resolve_credential_schema: Any,
    verify_inner: Any,
) -> Any:
    """Async twin of ``openvc.verify._check_schema``: opt-in, fail-closed only under
    ``require_schema``, awaiting the async schema validation."""
    if not credential.get("credentialSchema"):
        return None
    if resolve_credential_schema is None:
        if policy.require_schema:
            raise SchemaUnavailable(
                "credential declares a credentialSchema but no "
                "resolve_credential_schema was given "
                "(set policy.require_schema=False to skip)")
        return None
    return await validate_credential_schema_async(
        credential, resolve_credential_schema=resolve_credential_schema,
        verify_inner=verify_inner)


def _make_schema_verifier_async(
    policy: VerificationPolicy, resolver: Any, resolve_status_list: Any,
    resolve_status_list_token: Any, jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any,
    extra_contexts: Any, _depth: int,
) -> Any:
    """Async twin of ``openvc.verify._make_schema_verifier``: build the async
    ``verify_inner`` a ``JsonSchemaCredential`` uses, running the inner VC through
    ``verify_credential_async`` with schema OFF (bounded recursion) and the outer
    audience/type constraints dropped."""
    async def verify_inner(raw: bytes) -> dict[str, Any]:
        inner_policy = VerificationPolicy(
            leeway_s=policy.leeway_s,
            require_status=policy.require_status,
            now=policy.now,
        )
        result = await verify_credential_async(
            _bytes_to_credential(raw), policy=inner_policy, resolver=resolver,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            resolve_credential_schema=None,          # bound recursion
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            extra_contexts=extra_contexts, _depth=_depth + 1)
        return result.credential
    return verify_inner


__all__ = [
    "default_async_resolver",
    "verify_credential_async",
    "verify_many_async",
]
