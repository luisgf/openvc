"""
openvc.verify — the generic verification pipeline.

One call, :func:`verify_credential`, that

  1. **detects the format** — VC-JWT, SD-JWT VC, Data Integrity (eddsa-rdfc-2022 /
     ecdsa-sd-2023 over RDF, or eddsa-jcs-2022 / ecdsa-jcs-2019 over RFC 8785 JCS),
     or an enveloped VCDM 2.0 credential;
  2. **resolves the issuer key** via a :class:`~openvc.did.base.DidResolverRegistry`
     (JOSE formats peek the untrusted ``iss``/``kid``; Data Integrity resolves the
     proof's ``verificationMethod``);
  3. **verifies the proof** through the matching suite; and
  4. **applies a** :class:`VerificationPolicy` — expected type(s)/``vct``, audience
     and holder-binding for SD-JWT, ``proofPurpose`` for Data Integrity, and
     status-list revocation.

It turns the per-format proof suites into a single verifier. The EBSI glue
(:func:`openvc_ebsi.verify.verify_ebsi_badge`) is a specialisation of this shape
with the extra TIR trust step.

**Status is fail-closed by default** (``policy.require_status``). Every format is
checked against **both** status conventions — the W3C ``credentialStatus`` and the
IETF token ``status`` reference — so a status declared in the shape that does not
match the proof format is not silently skipped. If a status is declared and no
matching resolver is supplied, verification *fails* (:class:`StatusUnavailable`)
rather than skipping revocation — you opt out explicitly, not by omission. A
resolved *revoked* status raises :class:`~openvc.status.CredentialRevoked`; a
*suspended* one raises :class:`~openvc.status.CredentialSuspended`.

**Selective disclosure caveat:** for SD-JWT VC and ecdsa-sd-2023 the verifier only
sees what the holder discloses. A holder can withhold the ``credentialStatus`` /
``status`` claim entirely, in which case there is nothing to check and the
fail-closed gate cannot fire. An issuer that wants status enforced **must make it
mandatory / non-selectively-disclosable** (mark the pointer mandatory for
ecdsa-sd; keep it outside ``disclosable`` for SD-JWT).

**Data Integrity issuer binding:** the embedded-proof formats are accepted only
when the proof's ``verificationMethod`` is controlled by the credential's
``issuer`` (same DID) — otherwise anyone could sign a credential naming an
arbitrary issuer with their own key (:class:`IssuerBindingError`).

Errors: a proof/temporal/purpose failure raises a
:class:`~openvc.proof.errors.ProofError` subclass (shared by every suite); a
pipeline-level failure (unknown format, key resolution, type mismatch, missing
status resolver) raises a :class:`VerificationError` subclass; a revoked
credential raises :class:`~openvc.status.CredentialRevoked`.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Sequence, Union

if TYPE_CHECKING:
    from .did.base import DidResolverRegistry

from .cache import batch_resolvers
from .errors import OpenvcError
from .observability import logger, span
from .proof._verify_common import DEFAULT_LEEWAY_S
from .schema import (
    SchemaUnavailable,
    SchemaValidationResult,
    validate_credential_schema,
)
from .status import (
    CredentialRevoked,
    CredentialSuspended,
    StatusResult,
    TokenStatusResult,
    check_credential_status,
    check_token_status,
    parse_status_entries,
    parse_token_status_ref,
)

# --------------------------------------------------------------------------- #
# Format tags
# --------------------------------------------------------------------------- #

FORMAT_VC_JWT = "vc-jwt"
FORMAT_SD_JWT_VC = "sd-jwt-vc"
FORMAT_DI_EDDSA = "data-integrity:eddsa-rdfc-2022"
FORMAT_DI_ECDSA_SD = "data-integrity:ecdsa-sd-2023"
FORMAT_DI_EDDSA_JCS = "data-integrity:eddsa-jcs-2022"
FORMAT_DI_ECDSA_JCS = "data-integrity:ecdsa-jcs-2019"
FORMAT_DI_ECDSA_RDFC = "data-integrity:ecdsa-rdfc-2019"
FORMAT_ENVELOPED = "enveloped-verifiable-credential"

_CRYPTOSUITE_FORMAT = {
    "eddsa-rdfc-2022": FORMAT_DI_EDDSA,
    "ecdsa-sd-2023": FORMAT_DI_ECDSA_SD,
    "eddsa-jcs-2022": FORMAT_DI_EDDSA_JCS,
    "ecdsa-jcs-2019": FORMAT_DI_ECDSA_JCS,
    "ecdsa-rdfc-2019": FORMAT_DI_ECDSA_RDFC,
}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class VerificationError(OpenvcError):
    """A pipeline-level failure (not a proof-signature failure)."""


class UnknownCredentialFormat(VerificationError): ...
class KeyResolutionFailed(VerificationError): ...
class TypeMismatch(VerificationError): ...
class IssuerBindingError(VerificationError): ...


class StatusUnavailable(VerificationError):
    """The credential declares a status but no resolver was given and
    ``require_status`` is set (fail-closed)."""


# --------------------------------------------------------------------------- #
# Policy + result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerificationPolicy:
    """What to assert beyond the signature. All fields have safe defaults.

    ``require_status`` is **True** by default (fail-closed): a credential that
    declares a status but is verified without a resolver is rejected.
    ``require_schema`` is **False** by default (opt-in): ``credentialSchema`` is
    validated only when a ``resolve_credential_schema`` fetch is supplied; set it
    True to reject a credential that declares a schema but is verified without
    one. ``now`` pins the evaluation instant for Data Integrity temporal checks
    (the JOSE suites use the current time)."""
    leeway_s: int = DEFAULT_LEEWAY_S
    expected_types: Sequence[str] | None = None
    expected_vct: str | None = None
    audience: str | None = None
    nonce: str | None = None
    require_key_binding: bool = False
    proof_purpose: str = "assertionMethod"
    require_status: bool = True
    require_schema: bool = False
    now: datetime | None = None


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of a successful :func:`verify_credential`."""
    format: str
    credential: dict[str, Any]                 # the VC (SD-JWT: the disclosed claims)
    issuer: str | None
    subject: str | None
    claims: dict[str, Any] | None = None       # full JWT/SD-JWT claim set, if any
    key_bound: bool | None = None              # SD-JWT: a valid KB-JWT verified
    status: Union[StatusResult, TokenStatusResult, None] = None
    schema: SchemaValidationResult | None = None  # credentialSchema validation, if run
    raw: Any = None                            # the underlying suite result


@dataclass(frozen=True)
class BatchResult:
    """One credential's outcome in a :func:`verify_many` batch. On success *result* is set
    and *error* is ``None``; on a fail-closed verification failure *error* is set and
    *result* is ``None``. *index* is the credential's position in the input sequence, and
    *ok* is **derived** from *error* so it can never disagree with it."""
    index: int
    result: VerificationResult | None = None
    error: OpenvcError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


# --------------------------------------------------------------------------- #
# Default resolver
# --------------------------------------------------------------------------- #

def default_resolver() -> "DidResolverRegistry":
    """A :class:`DidResolverRegistry` with the offline ``did:key`` and ``did:jwk``
    resolvers and the SSRF-guarded ``did:web`` and ``did:webvh`` resolvers — the
    pipeline's default when none is passed. (``did:web`` / ``did:webvh`` only reach the
    network when such a DID is resolved.)"""
    from .did.base import DidResolverRegistry
    from .did.did_jwk import DidJwkResolver
    from .did.did_key import DidKeyResolver
    from .fetch import default_did_web_resolver, default_did_webvh_resolver
    return DidResolverRegistry(
        [DidKeyResolver(), DidJwkResolver(),
         default_did_web_resolver(), default_did_webvh_resolver()])


# --------------------------------------------------------------------------- #
# Format detection
# --------------------------------------------------------------------------- #

def detect_format(credential: Any) -> str:
    """Classify *credential* into one of the ``FORMAT_*`` tags. Raises
    :class:`UnknownCredentialFormat` if it matches nothing."""
    if isinstance(credential, str):
        if "~" in credential:
            return FORMAT_SD_JWT_VC              # SD-JWT: issuer-jwt ~ disclosures ~ kb
        if credential.count(".") == 2:
            return FORMAT_VC_JWT                 # a compact JWS
        raise UnknownCredentialFormat("string is neither a compact JWS nor an SD-JWT")

    if isinstance(credential, dict):
        types = credential.get("type", [])
        types = [types] if isinstance(types, str) else types
        if "EnvelopedVerifiableCredential" in types:
            return FORMAT_ENVELOPED
        proof = credential.get("proof")
        if isinstance(proof, dict):
            cryptosuite = proof.get("cryptosuite")
            fmt = _CRYPTOSUITE_FORMAT.get(cryptosuite) if isinstance(cryptosuite, str) else None
            if fmt is None:
                raise UnknownCredentialFormat(
                    f"unsupported Data Integrity cryptosuite {cryptosuite!r}")
            return fmt
        raise UnknownCredentialFormat(
            "dict has no `proof` and is not an EnvelopedVerifiableCredential")

    raise UnknownCredentialFormat(f"cannot verify a {type(credential).__name__}")


def _unwrap_enveloped(doc: dict[str, Any]) -> Any:
    """Extract the secured credential from a VCDM 2.0
    ``EnvelopedVerifiableCredential`` ``data:`` URL, ready to re-dispatch."""
    eid = doc.get("id")
    if not isinstance(eid, str) or not eid.startswith("data:"):
        raise UnknownCredentialFormat(
            "EnvelopedVerifiableCredential has no `data:` id to unwrap")
    meta, _, payload = eid[len("data:"):].partition(",")
    if not payload:
        raise UnknownCredentialFormat("enveloped `data:` id has no payload")
    params = meta.split(";")
    media = params[0]
    try:                                                 # attacker-controlled payload
        if "base64" in params[1:]:
            payload = base64.b64decode(payload).decode("utf-8")
        if media in ("application/vc+jwt", "application/jwt"):
            return payload                               # a compact JWS -> VC-JWT
        if "sd-jwt" in media:
            return payload                               # an SD-JWT string
        if media in ("application/vc+ld+json", "application/vc", "application/ld+json"):
            return json.loads(payload)                   # a JSON VC (embedded proof)
    except ValueError as exc:                            # bad base64 / utf-8 / JSON
        raise UnknownCredentialFormat(
            f"malformed enveloped payload for media {media!r}: {exc}") from exc
    raise UnknownCredentialFormat(f"unsupported enveloped media type {media!r}")


# --------------------------------------------------------------------------- #
# The pipeline
# --------------------------------------------------------------------------- #

def verify_credential(
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
    """Verify a credential in any supported format against *policy*.

    *resolver* (a ``DidResolver`` / ``DidResolverRegistry``) resolves a DID issuer
    key; it defaults to :func:`default_resolver` (offline ``did:key`` / ``did:jwk``
    + SSRF-guarded ``did:web``). *jwt_vc_issuer_fetch* opts into **https issuer**
    key discovery: when a JOSE credential's ``iss`` is an https URL, its key is
    resolved from ``/.well-known/jwt-vc-issuer`` using this fetch callable (pass
    :func:`openvc.fetch.https_json_fetch` for the SSRF-guarded one) — omit it and an
    https issuer raises. *x5c_trust_anchors* (a sequence of trusted root
    ``x509.Certificate`` objects) opts into **X.509 issuer trust**: when a JOSE
    header carries an ``x5c`` chain, it is validated to those anchors and bound to
    ``iss`` before its leaf key is used (see :mod:`openvc.x5c`). *resolve_status_list*
    fetches and **verifies** a W3C status-list credential (VC-JWT / Data Integrity);
    *resolve_status_list_token* the same for an IETF status-list token (SD-JWT).
    *resolve_credential_schema* opts into **JSON Schema validation**: when the
    credential declares a ``credentialSchema`` (``JsonSchema`` type), its schema is
    fetched with this callable (pass :func:`openvc.fetch.https_json_fetch`) and the
    credential validated against it — omit it and the schema is not checked unless
    ``policy.require_schema`` is set (see :mod:`openvc.schema`).
    *extra_contexts* is passed to the Data Integrity canonicaliser for offline
    non-bundled contexts.

    The status/schema resolvers are caller-injected, so ``openvc.fetch``'s SSRF
    guard protects those issuer-named URLs only if you pass a guarded fetch. Use the
    blessed defaults in :mod:`openvc.resolvers` (which fetch through the guarded
    https fetch and verify the fetched status list) for the safe drop-in; a custom
    resolver opts out of the guard.
    """
    policy = policy or VerificationPolicy()
    resolver = resolver if resolver is not None else default_resolver()

    fmt = detect_format(credential)
    logger.debug("verify: format=%s", fmt)
    with span("openvc.verify_credential", format=fmt):
        try:
            result = _verify_by_format(
                credential, fmt, policy, resolver, resolve_status_list,
                resolve_status_list_token, resolve_credential_schema,
                jwt_vc_issuer_fetch, x5c_trust_anchors, extra_contexts, _depth)
        except OpenvcError as exc:              # which check failed, no secrets
            logger.info("verify failed: format=%s error=%s", fmt, type(exc).__name__)
            raise
        logger.debug("verify ok: format=%s issuer=%s", result.format, result.issuer)
    return result


def _verify_by_format(
    credential: Any, fmt: str, policy: VerificationPolicy, resolver: Any,
    resolve_status_list: Any, resolve_status_list_token: Any,
    resolve_credential_schema: Any, jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any,
    extra_contexts: Any, _depth: int,
) -> VerificationResult:
    if fmt == FORMAT_ENVELOPED:
        if _depth >= 2:
            raise UnknownCredentialFormat("enveloped credential nested too deeply")
        return verify_credential(
            _unwrap_enveloped(credential), policy=policy, resolver=resolver,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            resolve_credential_schema=resolve_credential_schema,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            extra_contexts=extra_contexts, _depth=_depth + 1)

    # Closure the schema layer uses to verify a JsonSchemaCredential (the schema
    # wrapped in its own signed VC); built here where every resolver + _depth is in
    # scope, then threaded to the handler that runs _check_schema after the proof.
    verify_inner = _make_schema_verifier(
        policy, resolver, resolve_status_list, resolve_status_list_token,
        jwt_vc_issuer_fetch, x5c_trust_anchors, extra_contexts, _depth)

    if fmt == FORMAT_VC_JWT:
        return _verify_vc_jwt(
            credential, policy, resolver, resolve_status_list,
            resolve_status_list_token, resolve_credential_schema,
            jwt_vc_issuer_fetch, x5c_trust_anchors, verify_inner)
    if fmt == FORMAT_SD_JWT_VC:
        return _verify_sd_jwt(
            credential, policy, resolver, resolve_status_list,
            resolve_status_list_token, resolve_credential_schema,
            jwt_vc_issuer_fetch, x5c_trust_anchors, verify_inner)
    return _verify_data_integrity(
        credential, fmt, policy, resolver, resolve_status_list,
        resolve_status_list_token, resolve_credential_schema, extra_contexts,
        verify_inner)


def _make_schema_verifier(
    policy: VerificationPolicy, resolver: Any, resolve_status_list: Any,
    resolve_status_list_token: Any, jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any,
    extra_contexts: Any, _depth: int,
) -> Any:
    """Build the ``verify_inner`` closure the schema layer calls to verify a
    ``JsonSchemaCredential`` — the JSON Schema wrapped in its own signed VC.

    It runs the schema-defining VC through the **same** pipeline, so every format /
    DID / x5c / status resolver the caller wired applies to it too (fail-closed:
    an inner VC that declares a status but has no resolver still fails). Schema
    validation is **off** on that inner pass (``resolve_credential_schema=None``):
    the VC's own ``credentialSchema`` — the meta-schema — is not re-fetched, which
    bounds recursion so a hostile chain of schema-VCs cannot loop. The outer
    ``expected_types`` / ``expected_vct`` / ``audience`` / ``nonce`` constrain the
    *outer* credential, not this one, so the inner policy carries only the leeway,
    the evaluation instant, and the fail-closed-status knob."""
    def verify_inner(raw: bytes) -> dict[str, Any]:
        inner_policy = VerificationPolicy(
            leeway_s=policy.leeway_s,
            require_status=policy.require_status,
            now=policy.now,
        )
        return verify_credential(
            _bytes_to_credential(raw), policy=inner_policy, resolver=resolver,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            resolve_credential_schema=None,          # bound recursion (see docstring)
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            extra_contexts=extra_contexts, _depth=_depth + 1,
        ).credential
    return verify_inner


def _bytes_to_credential(raw: bytes) -> Any:
    """Turn the raw bytes fetched for a ``JsonSchemaCredential`` into a credential
    the pipeline can re-dispatch: the parsed JSON object for an embedded-proof VC,
    else the decoded string for a compact VC-JWT."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnknownCredentialFormat(
            f"JsonSchemaCredential bytes are not valid UTF-8: {exc}") from exc
    try:
        obj = json.loads(text)
    except ValueError:
        return text                       # not JSON -> a compact JWS (VC-JWT)
    return obj if isinstance(obj, dict) else text


def verify_many(
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
    """Verify many credentials in one call, resolving each distinct issuer DID / status
    list / schema / issuer-metadata URL **once** — roughly O(distinct issuers), not
    O(credentials). A 5-credential batch from one issuer resolves that DID once and
    fetches+verifies a shared status list once, via per-call caches
    (:func:`openvc.cache.batch_resolvers`), discarded when the call returns.

    Each credential is verified **independently and fail-closed**: a failure in one (bad
    signature, revoked, unresolvable key, malformed, …) becomes that item's ``error`` and
    never aborts the others. Returns one :class:`BatchResult` per input credential, in
    input order. Every keyword means exactly what it does in :func:`verify_credential`.

    Verification is **sequential** — the win is deduplicated resolution (each distinct
    issuer / status list resolved once), not parallelism; distinct issuers are still
    resolved one at a time.
    """
    resolver = resolver if resolver is not None else default_resolver()
    shared = batch_resolvers(
        resolver,
        resolve_status_list=resolve_status_list,
        resolve_status_list_token=resolve_status_list_token,
        resolve_credential_schema=resolve_credential_schema,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
    )
    out: list[BatchResult] = []
    ok_count = 0
    with span("openvc.verify_many", count=len(credentials)):
        for index, credential in enumerate(credentials):
            try:
                result = verify_credential(
                    credential, policy=policy, x5c_trust_anchors=x5c_trust_anchors,
                    extra_contexts=extra_contexts, **shared)
                out.append(BatchResult(index=index, result=result))
                ok_count += 1               # counted here so the debug args stay O(1)
            except OpenvcError as exc:          # per-credential fail-closed; one bad
                out.append(BatchResult(index=index, error=exc))  # item never aborts the rest
    logger.debug("verify_many: %d credentials, %d ok", len(out), ok_count)
    return out


# -- per-format handlers ---------------------------------------------------- #

def _verify_vc_jwt(token: str, policy: VerificationPolicy, resolver: Any,
                   resolve_status_list: Any, resolve_status_list_token: Any,
                   resolve_credential_schema: Any, jwt_vc_issuer_fetch: Any,
                   x5c_trust_anchors: Any, verify_inner: Any) -> VerificationResult:
    from .proof.vc_jwt import VcJwtProofSuite

    suite = VcJwtProofSuite(leeway_s=policy.leeway_s)
    iss, kid = suite.peek_issuer(token)
    jwk = _resolve_jose_key_with_x5c(
        token, iss, kid, sd_jwt=False, resolver=resolver,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors, now=policy.now)
    verified = suite.verify(token, public_key_jwk=jwk, audience=policy.audience)
    _check_types(verified.credential, policy.expected_types)
    # W3C status is in the vc object; an IETF `status` claim is in the JWT payload
    status = _check_status(verified.credential, verified.claims, policy,
                           resolve_status_list, resolve_status_list_token)
    schema = _check_schema(verified.credential, policy, resolve_credential_schema,
                           verify_inner)
    return VerificationResult(
        format=FORMAT_VC_JWT, credential=verified.credential, claims=verified.claims,
        issuer=verified.issuer, subject=verified.subject, status=status,
        schema=schema, raw=verified)


def _verify_sd_jwt(sd_jwt: str, policy: VerificationPolicy, resolver: Any,
                   resolve_status_list: Any, resolve_status_list_token: Any,
                   resolve_credential_schema: Any, jwt_vc_issuer_fetch: Any,
                   x5c_trust_anchors: Any, verify_inner: Any) -> VerificationResult:
    from .proof.sd_jwt import SdJwtVcProofSuite

    suite = SdJwtVcProofSuite(leeway_s=policy.leeway_s)
    iss, kid = suite.peek_issuer(sd_jwt)
    jwk = _resolve_jose_key_with_x5c(
        sd_jwt, iss, kid, sd_jwt=True, resolver=resolver,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors, now=policy.now)
    verified = suite.verify(
        sd_jwt, public_key_jwk=jwk, audience=policy.audience, nonce=policy.nonce,
        require_key_binding=policy.require_key_binding, expected_vct=policy.expected_vct)
    # the disclosed claims may carry either a W3C credentialStatus or an IETF status
    status = _check_status(verified.claims, verified.claims, policy,
                           resolve_status_list, resolve_status_list_token)
    # SD-JWT: only disclosed claims are visible; a withheld credentialSchema cannot
    # be validated (same selective-disclosure caveat as status).
    schema = _check_schema(verified.claims, policy, resolve_credential_schema,
                           verify_inner)
    return VerificationResult(
        format=FORMAT_SD_JWT_VC, credential=verified.claims, claims=verified.claims,
        issuer=verified.issuer, subject=_as_str(verified.claims.get("sub")),
        key_bound=verified.key_bound, status=status, schema=schema, raw=verified)


def _verify_data_integrity(
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

    # The JCS suites canonicalize with RFC 8785 (no JSON-LD term resolution), so —
    # unlike the RDF suites — they take no extra_contexts.
    if fmt in (FORMAT_DI_EDDSA_JCS, FORMAT_DI_ECDSA_JCS):
        verified = suite.verify(
            doc, resolver=resolver, expected_proof_purpose=policy.proof_purpose,
            now=policy.now)
    else:
        verified = suite.verify(
            doc, resolver=resolver, expected_proof_purpose=policy.proof_purpose,
            now=policy.now, extra_contexts=extra_contexts)
    _bind_issuer_to_verification_method(verified)
    _check_types(verified.credential, policy.expected_types)
    # DI credentials use W3C credentialStatus, but pass the doc as the IETF source
    # too so a (non-conformant) token `status` on one is not silently skipped
    status = _check_status(verified.credential, verified.credential, policy,
                           resolve_status_list, resolve_status_list_token)
    schema = _check_schema(verified.credential, policy, resolve_credential_schema,
                           verify_inner)
    return VerificationResult(
        format=fmt, credential=verified.credential, issuer=verified.issuer,
        subject=verified.subject, status=status, schema=schema, raw=verified)


# -- shared helpers --------------------------------------------------------- #

def _resolve_jose_key_with_x5c(
    token: str, iss: str, kid: str | None, *, sd_jwt: bool, resolver: Any,
    jwt_vc_issuer_fetch: Any, x5c_trust_anchors: Any, now: Any,
) -> dict[str, Any]:
    """Prefer an X.509 ``x5c`` header (validated to *x5c_trust_anchors* and bound to
    *iss*) when the caller opted into it and the token carries one; otherwise resolve
    the key from the issuer (DID registry or https well-known)."""
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
    return _resolve_jose_key(resolver, iss, kid, jwt_vc_issuer_fetch)


def _resolve_jose_key(
    resolver: Any, iss: str, kid: str | None, jwt_vc_issuer_fetch: Any = None
) -> dict[str, Any]:
    from .did.base import DidError

    # an https issuer is resolved via /.well-known/jwt-vc-issuer (opt-in), never
    # through the DID registry
    if iss.startswith("https://"):
        if jwt_vc_issuer_fetch is None:
            raise KeyResolutionFailed(
                f"issuer {iss!r} is an https URL; pass jwt_vc_issuer_fetch "
                "(e.g. openvc.fetch.https_json_fetch) to resolve its key")
        from .jwt_vc_issuer import JwtVcIssuerError, resolve_jwt_vc_issuer_key
        try:
            return resolve_jwt_vc_issuer_key(iss, kid, fetch=jwt_vc_issuer_fetch)
        # DidError covers the injected fetch's own SSRF / transport failures
        except (JwtVcIssuerError, DidError) as exc:
            raise KeyResolutionFailed(
                f"could not resolve issuer key for {iss!r}: {exc}") from exc

    try:
        doc = resolver.resolve(iss)
    except DidError as exc:
        raise KeyResolutionFailed(
            f"could not resolve issuer DID {iss!r}: {exc}") from exc
    vm = doc.key_by_kid(kid)
    if vm is None:
        raise KeyResolutionFailed(
            f"no verification method for kid {kid!r} in DID {iss!r}")
    return vm.public_key_jwk


def _bind_issuer_to_verification_method(verified: Any) -> None:
    """Bind a Data Integrity proof's ``verificationMethod`` to the credential's
    ``issuer``: the proof authenticates whoever controls that key, so its DID must
    equal the issuer's DID — otherwise a signer could name an arbitrary issuer and
    sign with their own key. (Delegated trust across DIDs is the job of a
    specialised verifier such as ``verify_ebsi_badge``, not this base pipeline.)"""
    issuer = verified.issuer
    proof = verified.proof if isinstance(verified.proof, dict) else {}
    vm = proof.get("verificationMethod")
    if not isinstance(issuer, str) or not issuer:
        raise IssuerBindingError("Data Integrity credential has no issuer to bind the key to")
    if not isinstance(vm, str) or vm.split("#", 1)[0] != issuer:
        raise IssuerBindingError(
            f"proof verificationMethod {vm!r} is not controlled by issuer {issuer!r}")


def _check_types(credential: dict[str, Any], expected: Sequence[str] | None) -> None:
    if not expected:
        return
    types = credential.get("type", [])
    types = [types] if isinstance(types, str) else types
    missing = [t for t in expected if t not in types]
    if missing:
        raise TypeMismatch(f"credential is missing required type(s): {missing}")


def _check_status(
    w3c_source: dict[str, Any],
    ietf_source: dict[str, Any] | None,
    policy: VerificationPolicy,
    resolve_status_list: Any,
    resolve_status_list_token: Any,
) -> Union[StatusResult, TokenStatusResult, None]:
    """Enforce BOTH status conventions the credential might declare — the W3C
    ``credentialStatus`` (on *w3c_source*) and the IETF ``status`` reference (on
    *ietf_source*, if any). Checking both for every format stops a status declared
    in the shape that does not match the proof format from being silently skipped.
    Returns the resolved result (W3C preferred), or None."""
    result: Union[StatusResult, TokenStatusResult, None] = None

    entries = parse_status_entries(w3c_source)
    if entries:
        if resolve_status_list is None:
            _fail_closed(policy, "credentialStatus", "resolve_status_list")
        else:
            w3c = check_credential_status(w3c_source, resolve_status_list=resolve_status_list)
            if w3c.revoked:
                raise CredentialRevoked(f"credential {w3c_source.get('id')!r} is revoked")
            if w3c.suspended:
                raise CredentialSuspended(f"credential {w3c_source.get('id')!r} is suspended")
            result = w3c
    elif w3c_source.get("credentialStatus") and policy.require_status:
        # a credentialStatus is declared but of an entry type we cannot check
        raise StatusUnavailable(
            "credential declares a credentialStatus of an unrecognised type "
            "(set policy.require_status=False to skip)")

    if ietf_source is not None:
        ref = parse_token_status_ref(ietf_source)
        if ref is not None:
            if resolve_status_list_token is None:
                _fail_closed(policy, "status reference", "resolve_status_list_token")
            else:
                ietf = check_token_status(
                    ietf_source, resolve_status_list_token=resolve_status_list_token)
                if ietf is not None:
                    if ietf.revoked:
                        raise CredentialRevoked("token is revoked")
                    if ietf.suspended:
                        raise CredentialSuspended("token is suspended")
                    result = result if result is not None else ietf
        elif ietf_source.get("status") is not None and policy.require_status:
            # a `status` claim is present but not a recognised reference -> fail closed
            raise StatusUnavailable(
                "credential declares a status of an unrecognised shape "
                "(set policy.require_status=False to skip)")

    return result


def _check_schema(
    credential: dict[str, Any],
    policy: VerificationPolicy,
    resolve_credential_schema: Any,
    verify_inner: Any,
) -> SchemaValidationResult | None:
    """Validate the credential against its declared ``credentialSchema`` (opt-in).

    Runs only when *resolve_credential_schema* is supplied. When the credential
    declares a schema but none is supplied, this is fail-closed **only** if
    ``policy.require_schema`` is set (schema conformance is data-shape, not a
    revocation gate — see :mod:`openvc.schema`); otherwise the schema is left
    unchecked. A malformed ``credentialSchema`` shape is not inspected unless the
    caller opted in, so a credential that merely carries one does not break
    verification for callers who never asked for schema validation. *verify_inner*
    lets the schema layer verify a ``JsonSchemaCredential`` (schema-in-a-VC) through
    this same pipeline."""
    if not credential.get("credentialSchema"):
        return None
    if resolve_credential_schema is None:
        if policy.require_schema:
            raise SchemaUnavailable(
                "credential declares a credentialSchema but no "
                "resolve_credential_schema was given "
                "(set policy.require_schema=False to skip)")
        return None
    return validate_credential_schema(
        credential, resolve_credential_schema=resolve_credential_schema,
        verify_inner=verify_inner)


def _fail_closed(policy: VerificationPolicy, declared: str, resolver_arg: str) -> None:
    """Raise (fail-closed) when a status is declared but its resolver is missing,
    unless the caller opted out via ``require_status=False``."""
    if policy.require_status:
        raise StatusUnavailable(
            f"credential declares a {declared} but no {resolver_arg} was given "
            "(set policy.require_status=False to skip)")


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


__all__ = [
    "FORMAT_DI_ECDSA_SD",
    "FORMAT_DI_EDDSA",
    "FORMAT_ENVELOPED",
    "FORMAT_SD_JWT_VC",
    "FORMAT_VC_JWT",
    "BatchResult",
    "IssuerBindingError",
    "KeyResolutionFailed",
    "StatusUnavailable",
    "TypeMismatch",
    "UnknownCredentialFormat",
    "VerificationError",
    "VerificationPolicy",
    "VerificationResult",
    "default_resolver",
    "detect_format",
    "verify_credential",
    "verify_many",
]
