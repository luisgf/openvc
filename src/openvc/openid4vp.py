"""
openvc.openid4vp — verify an OpenID4VP 1.0 ``vp_token`` response (stateless).

A **read/verify-only** verifier for the presentation half of OpenID for Verifiable
Presentations 1.0 (Final, 2025-07-09). Given the ``vp_token`` a wallet returned, the
``dcql_query`` the verifier sent, and the request's ``nonce`` + ``client_id``, it:

  1. validates the response shape — ``vp_token`` is a JSON object keyed by DCQL
     Credential Query ``id``; each value is an **array** of one or more Presentations
     (OpenID4VP 1.0 §8.1). Unknown keys, non-array values, and a single-valued query
     returning more than one Presentation are rejected;
  2. routes each Presentation to the matching proof suite by the query's ``format``
     — ``dc+sd-jwt`` (SD-JWT VC + KB-JWT) and ``jwt_vc_json`` (a W3C VP-JWT); and
  3. verifies each Presentation's proof **and its holder binding**: the transaction
     ``nonce`` and the audience ``client_id`` (OpenID4VP 1.0 §14.2). Per the spec the
     audience is the **full, prefixed** Client Identifier (e.g.
     ``x509_san_dns:client.example.org``), so *client_id* is compared verbatim.

This is deliberately **not** an OpenID4VP framework: it builds no Authorization
Request, hosts no ``request_uri``, and keeps no session/state — the verifier owns the
``nonce``/``client_id`` it issued and passes them in. Encrypted responses
(``direct_post.jwt``, a JWE) are a separate concern (issue #19); decrypt first, then
hand the plaintext ``vp_token`` object here — both transports converge on the same
shape (§8.3).

Scope of the credential formats: ``dc+sd-jwt``, ``jwt_vc_json`` and ``ldp_vc`` are
verified. An ``ldp_vc`` credential is presented as a **W3C Verifiable Presentation
secured with a Data Integrity proof** (OpenID4VP 1.0 §B.1): the holder binding is the
proof's ``authentication`` purpose with ``challenge`` = the request ``nonce`` and
``domain`` = the (full, prefixed) ``client_id``; the presentation's embedded
credentials are cascade-verified through :func:`openvc.verify_credential`. The RDF
cryptosuites (``eddsa-rdfc-2022`` / ``ecdsa-rdfc-2019``) need the ``[data-integrity]``
extra (``pyld``); the JCS ones (``eddsa-jcs-2022`` / ``ecdsa-jcs-2019``) do not.
``mso_mdoc`` (ISO mdoc) raises :class:`UnsupportedPresentationFormat` — a follow-up,
not silently skipped.

Credential-level revocation (status list) is out of scope for this layer: it verifies
the presentation binding and each credential's proof + validity window. Apply status
policy separately with :func:`openvc.verify_credential` on the returned credentials.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Mapping

from .errors import OpenvcError
from .proof._verify_common import DEFAULT_LEEWAY_S
from .proof.errors import ClaimsInvalid

if TYPE_CHECKING:
    from .keys import KeyAgreementKey

__all__ = [
    "verify_vp_token",
    "verify_encrypted_vp_response",
    "VerifiedPresentation",
    "VpTokenVerification",
    "OpenID4VPError",
    "VpTokenMalformed",
    "UnsupportedPresentationFormat",
    "FORMAT_SD_JWT_VC",
    "FORMAT_JWT_VC",
    "FORMAT_LDP_VC",
    "FORMAT_MSO_MDOC",
]

# DCQL Credential Format Identifiers (OpenID4VP 1.0 §10 "format_specific_parameters").
FORMAT_SD_JWT_VC = "dc+sd-jwt"      # SD-JWT VC + KB-JWT               (verified)
FORMAT_JWT_VC = "jwt_vc_json"       # W3C VC as a JWT -> a VP-JWT      (verified)
FORMAT_LDP_VC = "ldp_vc"            # W3C VC with Data Integrity -> LDP-VP (verified)
FORMAT_MSO_MDOC = "mso_mdoc"        # ISO 18013-5 mdoc                (unsupported)

_SUPPORTED_FORMATS = frozenset({FORMAT_SD_JWT_VC, FORMAT_JWT_VC, FORMAT_LDP_VC})

# Data Integrity cryptosuites accepted for an ldp_vc presentation's holder
# `authentication` proof — the whole-document suites (ecdsa-sd-2023 is
# selective-disclosure issuance, not a holder proof, so it is excluded).
_LDP_VP_CRYPTOSUITES = frozenset({
    "eddsa-rdfc-2022", "eddsa-jcs-2022", "ecdsa-rdfc-2019", "ecdsa-jcs-2019"})


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class OpenID4VPError(OpenvcError):
    """Base class for OpenID4VP ``vp_token`` verification failures."""


class VpTokenMalformed(OpenID4VPError):
    """The ``vp_token`` / ``dcql_query`` shape is invalid (not the wire contract)."""


class UnsupportedPresentationFormat(OpenID4VPError):
    """A DCQL ``format`` this verifier does not implement (``ldp_vc`` / ``mso_mdoc``)."""


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedPresentation:
    """One verified Presentation from the ``vp_token``.

    *credentials* is the tuple of verified credentials the Presentation carries — one
    :class:`~openvc.VerificationResult` for ``dc+sd-jwt`` (the SD-JWT VC itself), and
    the embedded credentials for a ``jwt_vc_json`` VP-JWT. *raw* is the underlying
    format-specific object (``VerifiedSdJwt`` or the VP-JWT ``VerifiedPresentation``).
    """
    query_id: str
    format: str
    holder: str | None
    credentials: tuple[Any, ...]
    raw: Any


@dataclass(frozen=True)
class VpTokenVerification:
    """The result of verifying a whole ``vp_token``: every Presentation verified and
    bound to the request's ``nonce`` + ``client_id``."""
    presentations: tuple[VerifiedPresentation, ...]

    def for_query(self, query_id: str) -> tuple[VerifiedPresentation, ...]:
        """The verified Presentation(s) returned for a DCQL Credential Query *id*."""
        return tuple(p for p in self.presentations if p.query_id == query_id)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

def verify_vp_token(
    vp_token: Mapping[str, Any] | str,
    *,
    dcql_query: Mapping[str, Any],
    nonce: str,
    client_id: str,
    resolver: Any = None,
    now: datetime | None = None,
    leeway_s: int = DEFAULT_LEEWAY_S,
    extra_contexts: Mapping[str, dict] | None = None,
    require_holder_binding: bool = False,
) -> VpTokenVerification:
    """Verify an OpenID4VP 1.0 ``vp_token`` against the query and request binding.

    *vp_token* is the response object (or its JSON string). *dcql_query* is the
    ``dcql_query`` sent in the Authorization Request. *nonce* and *client_id* are the
    request's values the holder binding must match — *client_id* is the **full,
    prefixed** Client Identifier (e.g. ``x509_san_dns:verifier.example``), compared
    verbatim against the KB-JWT / VP-JWT ``aud``. *resolver* resolves issuer/holder
    keys (a :class:`~openvc.did.base.DidResolverRegistry`); *now* pins the evaluation
    instant for the validity window.

    Returns a :class:`VpTokenVerification`. Raises :class:`VpTokenMalformed` on a
    shape violation, :class:`UnsupportedPresentationFormat` for ``mso_mdoc`` (and an
    ``ldp_vc`` presentation whose Data Integrity cryptosuite is not one of the
    whole-document suites), and the suite's own typed error (``SignatureInvalid`` /
    ``ClaimsInvalid`` / …) if any Presentation fails to verify or bind — a single
    failure rejects the whole response (fail closed). *extra_contexts* is passed to
    the Data Integrity path for ``ldp_vc`` presentations that reference JSON-LD
    contexts beyond the bundled ones (RDF cryptosuites only).

    Every Presentation is cryptographically holder-bound (the KB-JWT for
    ``dc+sd-jwt``, the holder signature for ``jwt_vc_json`` and ``ldp_vc``), and the
    reported ``holder`` is the **authenticated** identity — the KB/holder signer, not
    a self-asserted field. *require_holder_binding* additionally requires, for the W3C
    VP formats (``ldp_vc``, ``jwt_vc_json``), that every embedded credential was issued
    to that holder (``credentialSubject.id == holder``) — so a presenter cannot pass
    off a third party's credential as their own; off by default (a holder may
    legitimately present another party's credential).

    With no ``credential_sets``, every Credential Query is required and its absence is
    rejected. When the query *does* carry ``credential_sets``, per-query completeness
    is **not** enforced here (a follow-up): an empty ``vp_token`` is still rejected, but
    the caller MUST inspect :meth:`VpTokenVerification.for_query` to confirm the
    specific credentials it needs came back.
    """
    if not nonce:
        raise ClaimsInvalid("verify_vp_token requires a non-empty nonce")
    if not client_id:
        raise ClaimsInvalid("verify_vp_token requires a non-empty client_id")

    token = _parse_vp_token(vp_token)
    if not token:
        raise VpTokenMalformed("vp_token contains no presentations")
    queries = _index_dcql(dcql_query)
    _check_completeness(token, queries, dcql_query)

    verified: list[VerifiedPresentation] = []
    for query_id, presentations in token.items():
        query = queries.get(query_id)
        if query is None:
            raise VpTokenMalformed(
                f"vp_token key {query_id!r} is not a Credential Query id in the DCQL query")
        for presentation in _presentation_list(query_id, query, presentations):
            verified.append(_verify_one(
                query_id, query, presentation,
                nonce=nonce, client_id=client_id, resolver=resolver,
                now=now, leeway_s=leeway_s, extra_contexts=extra_contexts,
                require_holder_binding=require_holder_binding))
    return VpTokenVerification(presentations=tuple(verified))


def verify_encrypted_vp_response(
    response: str,
    *,
    key: "KeyAgreementKey",
    dcql_query: Mapping[str, Any],
    nonce: str,
    client_id: str,
    resolver: Any = None,
    now: datetime | None = None,
    leeway_s: int = DEFAULT_LEEWAY_S,
    extra_contexts: Mapping[str, dict] | None = None,
    require_holder_binding: bool = False,
) -> VpTokenVerification:
    """Decrypt a HAIP ``direct_post.jwt`` response (a JWE) and verify its ``vp_token``.

    *response* is the compact JWE from the ``response`` form field; *key* is the
    verifier's :class:`~openvc.keys.KeyAgreementKey` (the private half of the
    encryption key it published in ``client_metadata``). The JWE is decrypted (direct
    ``ECDH-ES`` + ``A128GCM`` / ``A256GCM`` on P-256, allow-listed before any crypto —
    see :mod:`openvc.jwe`); the plaintext is the OpenID4VP response object, whose
    ``vp_token`` is then verified exactly as :func:`verify_vp_token` (same *nonce* /
    *client_id* binding). The response ``state`` is **not** checked here — match it to
    your session yourself (call :func:`openvc.jwe.decrypt_compact` if you need the raw
    response object). Raises :class:`~openvc.jwe.JweError` on a decryption failure and
    the same errors as :func:`verify_vp_token` thereafter.
    """
    from .jwe import decrypt_compact

    plaintext = decrypt_compact(response, key=key)
    try:
        payload = json.loads(plaintext)
    except (ValueError, RecursionError) as exc:
        raise VpTokenMalformed(f"decrypted response is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping) or "vp_token" not in payload:
        raise VpTokenMalformed("decrypted response has no vp_token member")
    return verify_vp_token(
        payload["vp_token"], dcql_query=dcql_query, nonce=nonce, client_id=client_id,
        resolver=resolver, now=now, leeway_s=leeway_s, extra_contexts=extra_contexts,
        require_holder_binding=require_holder_binding)


def _parse_vp_token(vp_token: Mapping[str, Any] | str) -> Mapping[str, Any]:
    if isinstance(vp_token, str):
        try:
            vp_token = json.loads(vp_token)
        except (ValueError, RecursionError) as exc:
            raise VpTokenMalformed(f"vp_token is not valid JSON: {exc}") from exc
    if not isinstance(vp_token, Mapping):
        raise VpTokenMalformed(
            "vp_token must be a JSON object keyed by Credential Query id")
    return vp_token


def _index_dcql(dcql_query: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if not isinstance(dcql_query, Mapping):
        raise VpTokenMalformed("dcql_query must be a JSON object")
    credentials = dcql_query.get("credentials")
    if not isinstance(credentials, list) or not credentials:
        raise VpTokenMalformed("dcql_query.credentials must be a non-empty array")
    queries: dict[str, Mapping[str, Any]] = {}
    for entry in credentials:
        if not isinstance(entry, Mapping):
            raise VpTokenMalformed("each dcql_query.credentials entry must be an object")
        query_id = entry.get("id")
        fmt = entry.get("format")
        if not isinstance(query_id, str) or not query_id:
            raise VpTokenMalformed("each Credential Query needs a non-empty string id")
        if not isinstance(fmt, str) or not fmt:
            raise VpTokenMalformed(f"Credential Query {query_id!r} needs a string format")
        if query_id in queries:
            raise VpTokenMalformed(f"duplicate Credential Query id {query_id!r}")
        queries[query_id] = entry
    return queries


def _check_completeness(
    token: Mapping[str, Any], queries: Mapping[str, Any],
    dcql_query: Mapping[str, Any],
) -> None:
    # With no credential_sets, every Credential Query is required (OpenID4VP 1.0 §7);
    # optionality via credential_sets is a follow-up, so only enforce the simple case.
    if dcql_query.get("credential_sets"):
        return
    missing = [qid for qid in queries if qid not in token]
    if missing:
        raise VpTokenMalformed(
            f"vp_token is missing required Credential Query id(s): {sorted(missing)}")


def _presentation_list(query_id: str, query: Mapping[str, Any], value: Any) -> list[Any]:
    # OpenID4VP 1.0 §8.1: the value is ALWAYS an array; length 1 unless multiple:true.
    if not isinstance(value, list):
        raise VpTokenMalformed(
            f"vp_token[{query_id!r}] must be an array of Presentations")
    if not value:
        raise VpTokenMalformed(f"vp_token[{query_id!r}] is an empty array")
    if not query.get("multiple", False) and len(value) != 1:
        raise VpTokenMalformed(
            f"Credential Query {query_id!r} is single-valued but returned {len(value)} "
            f"Presentations (set multiple:true to allow more)")
    return value


def _verify_one(
    query_id: str, query: Mapping[str, Any], presentation: Any, *,
    nonce: str, client_id: str, resolver: Any, now: datetime | None, leeway_s: int,
    extra_contexts: Mapping[str, dict] | None, require_holder_binding: bool,
) -> VerifiedPresentation:
    fmt = query["format"]
    if fmt == FORMAT_SD_JWT_VC:
        return _verify_sd_jwt_vc(
            query_id, query, presentation,
            nonce=nonce, client_id=client_id, resolver=resolver, now=now, leeway_s=leeway_s)
    if fmt == FORMAT_JWT_VC:
        return _verify_jwt_vp(
            query_id, presentation,
            nonce=nonce, client_id=client_id, resolver=resolver, leeway_s=leeway_s,
            require_holder_binding=require_holder_binding)
    if fmt == FORMAT_LDP_VC:
        return _verify_ldp_vp(
            query_id, presentation, nonce=nonce, client_id=client_id, resolver=resolver,
            now=now, leeway_s=leeway_s, extra_contexts=extra_contexts,
            require_holder_binding=require_holder_binding)
    if fmt == FORMAT_MSO_MDOC:
        raise UnsupportedPresentationFormat(
            f"Credential Query {query_id!r} format {fmt!r} is not yet supported")
    raise UnsupportedPresentationFormat(
        f"Credential Query {query_id!r} has unknown format {fmt!r}")


def _verify_sd_jwt_vc(
    query_id: str, query: Mapping[str, Any], presentation: Any, *,
    nonce: str, client_id: str, resolver: Any, now: datetime | None, leeway_s: int,
) -> VerifiedPresentation:
    from .verify import (
        FORMAT_SD_JWT_VC as _PIPELINE_SD_JWT,
        VerificationPolicy,
        verify_credential,
    )

    if not isinstance(presentation, str):
        raise VpTokenMalformed(
            f"a {FORMAT_SD_JWT_VC} Presentation for {query_id!r} must be a compact string")
    # Pin the query's format to an actual SD-JWT. verify_credential re-detects the
    # format from the string, and only the SD-JWT path runs the KB-JWT nonce/aud
    # binding — so a plain VC-JWT smuggled under a dc+sd-jwt query would otherwise be
    # verified with NO nonce binding (a cross-session replay with an unbound holder).
    # An SD-JWT always carries a '~'; reject anything else before verifying.
    if "~" not in presentation:
        raise VpTokenMalformed(
            f"a {FORMAT_SD_JWT_VC} Presentation for {query_id!r} must be an SD-JWT")
    # Holder binding is required unless the query opted out (default true, §10.4).
    require_binding = bool(query.get("require_cryptographic_holder_binding", True))
    policy = VerificationPolicy(
        audience=client_id, nonce=nonce, require_key_binding=require_binding,
        require_status=False, now=now, leeway_s=leeway_s)
    result = verify_credential(presentation, policy=policy, resolver=resolver)
    if result.format != _PIPELINE_SD_JWT:            # defence in depth vs re-detection
        raise VpTokenMalformed(
            f"Presentation for {query_id!r} did not verify as an SD-JWT VC "
            f"(got {result.format!r})")
    _check_vct(query_id, query, getattr(result.raw, "vct", None))
    holder = result.subject
    return VerifiedPresentation(
        query_id=query_id, format=FORMAT_SD_JWT_VC, holder=holder,
        credentials=(result,), raw=result.raw)


def _verify_jwt_vp(
    query_id: str, presentation: Any, *,
    nonce: str, client_id: str, resolver: Any, leeway_s: int,
    require_holder_binding: bool = False,
) -> VerifiedPresentation:
    from .proof.vp_jwt import VpJwtProofSuite

    if not isinstance(presentation, str):
        raise VpTokenMalformed(
            f"a {FORMAT_JWT_VC} Presentation for {query_id!r} must be a compact JWT string")
    # resolver mode authenticates the holder from `iss`, so require_holder_binding binds
    # subject==holder without needing expected_holder (VP-JWT enforces that invariant).
    verified = VpJwtProofSuite(leeway_s=leeway_s).verify(
        presentation, audience=client_id, nonce=nonce, resolver=resolver,
        require_holder_binding=require_holder_binding)
    return VerifiedPresentation(
        query_id=query_id, format=FORMAT_JWT_VC, holder=verified.holder,
        credentials=tuple(verified.credentials), raw=verified)


def _verify_ldp_vp(
    query_id: str, presentation: Any, *,
    nonce: str, client_id: str, resolver: Any, now: datetime | None, leeway_s: int,
    extra_contexts: Mapping[str, dict] | None, require_holder_binding: bool,
) -> VerifiedPresentation:
    from .verify import VerificationPolicy, verify_credential

    # OpenID4VP 1.0 §B.1: an ldp_vc credential is presented as a W3C Verifiable
    # Presentation secured with a Data Integrity `authentication` proof — the value is
    # the VP JSON object (not a string). Pin that shape so a holder-unbound bare
    # credential cannot be smuggled under an ldp_vc query (the LDP analogue of the
    # dc+sd-jwt "must be an SD-JWT" pin): the binding lives ONLY on a VP proof.
    if isinstance(presentation, str):
        raise VpTokenMalformed(
            f"an {FORMAT_LDP_VC} Presentation for {query_id!r} must be a JSON object "
            f"(a W3C Verifiable Presentation), not a string")
    if not isinstance(presentation, Mapping):
        raise VpTokenMalformed(
            f"an {FORMAT_LDP_VC} Presentation for {query_id!r} must be a JSON object")
    types = presentation.get("type")
    type_list = ([types] if isinstance(types, str)
                 else types if isinstance(types, list) else [])
    if "VerifiablePresentation" not in type_list:
        raise VpTokenMalformed(
            f"an {FORMAT_LDP_VC} Presentation for {query_id!r} must be a "
            f"VerifiablePresentation")

    proof = presentation.get("proof")
    if isinstance(proof, list):
        raise UnsupportedPresentationFormat(
            f"the {FORMAT_LDP_VC} Presentation for {query_id!r} carries multiple proofs "
            f"(not supported)")
    if not isinstance(proof, Mapping):
        raise VpTokenMalformed(
            f"the {FORMAT_LDP_VC} Presentation for {query_id!r} has no Data Integrity "
            f"holder proof")
    cryptosuite = proof.get("cryptosuite")
    if cryptosuite not in _LDP_VP_CRYPTOSUITES:
        raise UnsupportedPresentationFormat(
            f"the {FORMAT_LDP_VC} Presentation for {query_id!r} uses an unsupported "
            f"Data Integrity cryptosuite {cryptosuite!r}")

    # Verify the holder's authentication proof, bound to the request: challenge = the
    # transaction nonce, domain = the full prefixed client_id. The holder key is
    # resolved from the proof's verificationMethod and must be authorized for
    # `authentication` in its DID document (the suite enforces this).
    suite = _di_suite_for(str(cryptosuite), leeway_s)
    verify_kwargs: dict[str, Any] = dict(
        resolver=resolver, expected_proof_purpose="authentication",
        expected_challenge=nonce, expected_domain=client_id, now=now)
    if cryptosuite in ("eddsa-rdfc-2022", "ecdsa-rdfc-2019"):   # RDF suites take contexts
        verify_kwargs["extra_contexts"] = extra_contexts
    verified_vp = suite.verify(dict(presentation), **verify_kwargs)

    # The AUTHENTICATED holder is the controller of the verificationMethod whose key
    # just signed (and was authorised for `authentication`) — never the self-asserted
    # `holder` field. Binding + reporting must key off the signer so a caller's
    # "did the presenter own this credential?" check cannot be spoofed.
    holder = _vp_holder(query_id, presentation, verified_vp.proof)

    # Cascade-verify each embedded credential through the pipeline (fail closed).
    policy = VerificationPolicy(require_status=False, now=now, leeway_s=leeway_s)
    credentials = tuple(
        verify_credential(vc, policy=policy, resolver=resolver,
                          extra_contexts=extra_contexts)
        for vc in _embedded_vcs(query_id, presentation))

    # Optional subject binding: require each embedded credential to have been issued
    # to the authenticated holder (the presenter owns what they present).
    if require_holder_binding:
        for result in credentials:
            if not result.subject or result.subject != holder:
                raise ClaimsInvalid(
                    f"credential subject {result.subject!r} is not the authenticated "
                    f"holder {holder!r} (require_holder_binding)")

    return VerifiedPresentation(
        query_id=query_id, format=FORMAT_LDP_VC, holder=holder,
        credentials=credentials, raw=verified_vp)


def _di_suite_for(cryptosuite: str, leeway_s: int) -> Any:
    # cryptosuite is pre-validated against _LDP_VP_CRYPTOSUITES by the caller.
    if cryptosuite == "eddsa-rdfc-2022":
        from .proof.data_integrity import DataIntegrityProofSuite
        return DataIntegrityProofSuite(leeway_s=leeway_s)
    if cryptosuite == "eddsa-jcs-2022":
        from .proof.di_jcs import EddsaJcsProofSuite
        return EddsaJcsProofSuite(leeway_s=leeway_s)
    if cryptosuite == "ecdsa-jcs-2019":
        from .proof.di_jcs import EcdsaJcsProofSuite
        return EcdsaJcsProofSuite(leeway_s=leeway_s)
    from .proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite      # ecdsa-rdfc-2019
    return EcdsaRdfcProofSuite(leeway_s=leeway_s)


def _embedded_vcs(query_id: str, presentation: Mapping[str, Any]) -> list[Any]:
    # VCDM: `verifiableCredential` is one credential or an array. A presentation
    # answering a Credential Query must carry at least one. Each item is a VC string
    # (VC-JWT / SD-JWT) or a JSON object (Data Integrity / EnvelopedVerifiableCredential)
    # — verify_credential re-detects the format.
    vc = presentation.get("verifiableCredential")
    items = vc if isinstance(vc, list) else ([vc] if vc is not None else [])
    if not items:
        raise VpTokenMalformed(
            f"the {FORMAT_LDP_VC} Presentation for {query_id!r} embeds no "
            f"verifiableCredential")
    for item in items:
        if not isinstance(item, (str, Mapping)):
            raise VpTokenMalformed(
                f"each embedded credential in {query_id!r} must be a string or JSON object")
    return items


def _vp_holder(
    query_id: str, presentation: Mapping[str, Any], proof: Mapping[str, Any]
) -> str | None:
    # The authenticated holder is the DID that controls the verificationMethod whose
    # key signed the authentication proof. A self-asserted `holder` field, if present,
    # MUST equal it — else a presenter could sign with their own key while labelling
    # the presentation as a victim (mirrors the VP-JWT `vp.holder == iss` check).
    vm = proof.get("verificationMethod")
    authenticated = vm.split("#", 1)[0] if isinstance(vm, str) else None
    claimed = presentation.get("holder")
    if isinstance(claimed, Mapping):
        claimed = claimed.get("id")
    if isinstance(claimed, str) and claimed and authenticated and claimed != authenticated:
        raise ClaimsInvalid(
            f"the {FORMAT_LDP_VC} Presentation for {query_id!r} claims holder "
            f"{claimed!r} but was authenticated by {authenticated!r}")
    return authenticated


def _check_vct(query_id: str, query: Mapping[str, Any], vct: str | None) -> None:
    # DCQL meta.vct_values constrains the acceptable SD-JWT VC type(s) (§6.3.1); if the
    # query named them, the disclosed vct MUST be one of them — the "right credential".
    meta = query.get("meta")
    vct_values = meta.get("vct_values") if isinstance(meta, Mapping) else None
    if vct_values is None:
        return
    # A malformed constraint fails safe (VpTokenMalformed) rather than silently widening.
    if (not isinstance(vct_values, list) or not vct_values
            or not all(isinstance(v, str) for v in vct_values)):
        raise VpTokenMalformed(
            f"Credential Query {query_id!r}: meta.vct_values must be a non-empty array "
            f"of strings")
    if vct not in vct_values:
        raise ClaimsInvalid(
            f"Credential Query {query_id!r}: vct {vct!r} is not one of the requested "
            f"vct_values")
