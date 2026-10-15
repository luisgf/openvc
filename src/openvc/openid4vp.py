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
     — ``dc+sd-jwt`` (SD-JWT VC + KB-JWT) and ``jwt_vc_json`` (a W3C VP-JWT, or — when
     the query opts out of holder binding — a bare VC-JWT); and
  3. verifies each Presentation's proof **and its holder binding**: the transaction
     ``nonce`` and the audience (OpenID4VP 1.0 §14.2). The audience is either the
     **full, prefixed** Client Identifier (e.g. ``x509_san_dns:client.example.org``,
     the redirect / ``direct_post`` flow — pass *client_id*), or — over the **W3C
     Digital Credentials API** — the calling web ``origin:<origin>`` (Appendix A; pass
     *expected_origins*). Exactly one is given. Unless the Credential Query sets
     ``require_cryptographic_holder_binding`` to ``false``, every credential a W3C
     presentation carries must also be bound to its authenticated holder (§B.1). A query
     that sets it to ``false`` may be answered with a bare Verifiable Credential instead,
     which carries no audience, nonce or holder (§B.1; see :func:`verify_vp_token`).

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
extra (``pyld``); the JCS ones (``eddsa-jcs-2022`` / ``ecdsa-jcs-2019``) do not. With
holder binding waived, an ``ldp_vc`` answer may instead be a bare Data Integrity
credential.
``mso_mdoc`` (ISO 18013-5 mdoc) is verified over the **W3C Digital Credentials API**
flow via :mod:`openvc.mdoc`: pass *trust_anchors* (the IACA roots) and *expected_origins*,
and the holder binding is the ``DeviceAuth`` over the origin-bound ``SessionTranscript``
this module builds. It ships **experimental** (ADR-0005) until interop-tested against the
EUDI reference wallet; the redirect / ``direct_post`` mdoc handover is not yet wired.

Credential status (revocation / suspension) is checked when the caller passes
*resolve_status_list* / *resolve_status_list_token*: every ``dc+sd-jwt``,
``jwt_vc_json`` and ``ldp_vc`` credential, nested ones included, goes through
:func:`openvc.verify_credential`'s status check. Without a resolver a declared status
is skipped unless *require_status* is set, which defaults to ``False`` here (unlike
:class:`~openvc.VerificationPolicy`, which fails closed by default). An ``mso_mdoc``'s
status is not checked by this layer.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from . import _json
from .errors import OpenvcError
from .proof._verify_common import (
    DEFAULT_KB_MAX_AGE_S,
    DEFAULT_LEEWAY_S,
    non_negative_seconds,
    safe_repr,
)
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
    "VpTokenIncomplete",
    "UnsupportedPresentationFormat",
    "dcapi_session_transcript",
    "FORMAT_SD_JWT_VC",
    "FORMAT_JWT_VC",
    "FORMAT_LDP_VC",
    "FORMAT_MSO_MDOC",
]

# DCQL Credential Format Identifiers (OpenID4VP 1.0 §10 "format_specific_parameters").
FORMAT_SD_JWT_VC = "dc+sd-jwt"      # SD-JWT VC + KB-JWT               (verified)
FORMAT_JWT_VC = "jwt_vc_json"       # W3C VC as a JWT -> a VP-JWT, or a bare VC-JWT (verified)
FORMAT_LDP_VC = "ldp_vc"            # W3C VC with Data Integrity -> LDP-VP, or a bare VC (verified)
FORMAT_MSO_MDOC = "mso_mdoc"        # ISO 18013-5 mdoc  (verified, experimental; DC API)

_SUPPORTED_FORMATS = frozenset({FORMAT_SD_JWT_VC, FORMAT_JWT_VC, FORMAT_LDP_VC})

# What a jwt_vc_json / ldp_vc answer is, decided by _w3c_shape before anything is verified.
_SHAPE_VP = "vp"        # a Verifiable Presentation, or whatever the VP lanes judge themselves
_SHAPE_VC = "vc"        # a bare Verifiable Credential (OpenID4VP 1.0 §B.1, #204)

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


class VpTokenIncomplete(VpTokenMalformed):
    """The ``vp_token`` is well-formed but does not answer what the ``dcql_query`` requires
    (OpenID4VP 1.0 §6.4.2, §8.6): a Credential Query is missing when the query has no
    ``credential_sets`` (every query is required), or no option of a required Credential
    Set Query has every one of its Credential Query ids answered. A subclass of
    :class:`VpTokenMalformed`, so an ``except VpTokenMalformed`` keeps catching it. Raised
    before any Presentation is read, so it says nothing about the Presentations."""


class UnsupportedPresentationFormat(OpenID4VPError):
    """A DCQL ``format``, flow or proof this verifier does not implement: an unknown
    ``format``, an ``ldp_vc`` presentation with an unsupported cryptosuite or several
    proofs, or an ``mso_mdoc`` outside the Digital Credentials API flow."""


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

    A **bare credential** (a ``jwt_vc_json`` / ``ldp_vc`` query that waived holder
    binding, answered with a Verifiable Credential and no presentation) reports
    ``holder=None``, as ``mso_mdoc`` does: nothing authenticated a holder. *credentials*
    is the one verified credential and *raw* its suite's own result (``VerifiedCredential``).
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

def _dc_api_accepted_auds(
    client_id: str | None, expected_origins: Sequence[str] | None,
) -> frozenset[str] | None:
    """Validate the audience inputs and, for the DC API flow, return the accepted
    ``origin:<origin>`` audience set. Exactly one of *client_id* (redirect / direct_post)
    or *expected_origins* (Digital Credentials API) must be given."""
    if (client_id is None) == (expected_origins is None):
        raise ClaimsInvalid(
            "pass exactly one of client_id (redirect / direct_post) or "
            "expected_origins (the W3C Digital Credentials API)")
    if expected_origins is not None:
        # A bare str is a Sequence[str] that iterates into single characters — reject it
        # (and any non-list/tuple, empty, or blank/whitespace origin) so a single origin
        # passed as a string is a hard error, not silently split into per-character origins.
        if (isinstance(expected_origins, (str, bytes))
                or not isinstance(expected_origins, (list, tuple))
                or not expected_origins
                or not all(isinstance(o, str) and o and o == o.strip() for o in expected_origins)):
            raise ClaimsInvalid(
                "expected_origins must be a non-empty list/tuple of non-blank origin strings")
        return frozenset("origin:" + o for o in expected_origins)
    if not client_id:
        raise ClaimsInvalid("verify_vp_token requires a non-empty client_id")
    return None


def verify_vp_token(
    vp_token: Mapping[str, Any] | str,
    *,
    dcql_query: Mapping[str, Any],
    nonce: str,
    client_id: str | None = None,
    expected_origins: Sequence[str] | None = None,
    trust_anchors: Sequence[Any] | None = None,
    mdoc_jwk_thumbprint: bytes | None = None,
    resolver: Any = None,
    now: datetime | None = None,
    leeway_s: int = DEFAULT_LEEWAY_S,
    extra_contexts: Mapping[str, dict] | None = None,
    require_holder_binding: bool = False,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
) -> VpTokenVerification:
    """Verify an OpenID4VP 1.0 ``vp_token`` against the query and request binding.

    *vp_token* is the response object (or its JSON string). *dcql_query* is the
    ``dcql_query`` sent in the Authorization Request. *nonce* is the request's
    transaction nonce, bound on every Presentation.

    Pass **exactly one** of *client_id* or *expected_origins* — the audience the holder
    binding must match:

    * *client_id* — the redirect / ``direct_post`` flow: the **full, prefixed** Client
      Identifier (e.g. ``x509_san_dns:verifier.example``), compared verbatim against the
      KB-JWT / VP-JWT ``aud``.
    * *expected_origins* — the **W3C Digital Credentials API** flow (``dc_api`` response
      mode): a DC-API-delivered response binds to the **calling web origin**, so per
      OpenID4VP 1.0 Appendix A the audience is always ``origin:<origin>`` (never the
      client_id). Pass the origins your verifier serves (e.g. ``["https://verifier.example"]``);
      a Presentation is accepted only if its signed ``aud`` is ``origin:<o>`` for an *o*
      in the list. CIR (EU) 2025/1569 pins remote presentation to OpenID4VP + the DC API.

    *resolver* resolves issuer/holder keys (a :class:`~openvc.did.base.DidResolverRegistry`);
    *now* pins the evaluation instant for the validity window, and for the SD-JWT VC
    Key Binding JWT's freshness window: its ``iat`` must be no older than
    *kb_max_age_s* (default 300 s) plus *leeway_s*, and not in the future (RFC 9901
    §7.3 step 5.5). It applies to SD-JWT VCs nested in ``jwt_vc_json`` / ``ldp_vc``
    presentations too. To verify an archived response, pin *now* to the receipt time
    your system recorded — never to a value read from the response itself. A naive
    *now* is UTC.

    An ``mso_mdoc`` Presentation (ISO 18013-5, **experimental**) is verified over the
    Digital Credentials API flow: pass *trust_anchors* (the IACA root
    :class:`~cryptography.x509.Certificate` objects the document signer must chain to) and
    *expected_origins*; the value is a base64url ``DeviceResponse`` and the ``DeviceAuth``
    is bound to the origin-bound ``SessionTranscript`` (:func:`dcapi_session_transcript`),
    tried against each expected origin. *mdoc_jwk_thumbprint* is the verifier's
    response-encryption key thumbprint for that transcript (``None`` when unencrypted).
    The verified :class:`VerifiedPresentation` carries one :class:`openvc.mdoc.VerifiedMdoc`
    per document in ``credentials``.

    Returns a :class:`VpTokenVerification`. Raises :class:`VpTokenMalformed` on a
    shape violation, :class:`UnsupportedPresentationFormat` for an ``ldp_vc`` presentation
    whose Data Integrity cryptosuite is not one of the whole-document suites (or an
    ``mso_mdoc`` outside the Digital Credentials API flow), a typed
    :class:`openvc.mdoc.MdocError` if an mdoc fails to verify or bind, and the suite's own
    typed error (``SignatureInvalid`` /
    ``ClaimsInvalid`` / …) if any Presentation fails to verify or bind — a single
    failure rejects the whole response (fail closed). *extra_contexts* supplies JSON-LD
    contexts beyond the bundled ones (``url -> document``; nothing is fetched): the Data
    Integrity path uses them for ``ldp_vc`` presentations (RDF cryptosuites), and the
    ``meta.type_values`` match below uses them for both W3C formats.

    A Credential Query's DCQL constraint on the credential type is enforced per format:
    ``meta.vct_values`` (``dc+sd-jwt``), ``meta.doctype_value`` (``mso_mdoc``) and
    ``meta.type_values`` (``jwt_vc_json`` / ``ldp_vc``). For ``type_values`` **every**
    credential the presentation embeds must have, among its fully expanded types, all the
    IRIs of at least one alternative (OpenID4VP 1.0 §B.1.1), else ``ClaimsInvalid``. The
    types are expanded with JSON-LD against the credential's own ``@context``, so the
    query names IRIs: ``VerifiableCredential`` expands to
    ``https://www.w3.org/2018/credentials#VerifiableCredential``, while a term no context
    defines stays as written. Expanding needs the ``[data-integrity]`` extra (``pyld``)
    and every context the credential cites — only the VCDM 2.0 context is bundled. A
    nested SD-JWT never matches. A query with no ``meta``, or whose ``meta`` lacks the
    key, puts no constraint on the type. A malformed constraint is
    :class:`VpTokenMalformed`, for all three formats and before any Presentation is
    verified: a ``meta`` that is not a JSON object, or a constraint that is present
    but ``null`` or the wrong shape, never reads as "no constraint". Every query is
    checked, answered or not (a query the wallet left out under ``credential_sets``
    included), so one malformed alternative fails on every response, not only on the
    day a wallet answers it. A format openvc does not know, and the keys of another
    format, are not read. A well-formed ``type_values`` needs ``pyld`` only when its
    query is answered.
    Like ``vct_values``, the check selects the right credential type, not a trusted
    issuer: check each result's ``issuer`` yourself.

    Every Presentation is cryptographically holder-bound (the KB-JWT for
    ``dc+sd-jwt``, the holder signature for ``jwt_vc_json`` and ``ldp_vc``), unless a W3C
    query waives it and the answer is a bare credential (below). For the W3C
    VP formats (``jwt_vc_json`` / ``ldp_vc``) the reported ``holder`` is the
    **authenticated signer** — the controller of the verificationMethod whose key signed,
    never a self-asserted field. For ``dc+sd-jwt`` it is the issuer-signed ``sub``: the
    KB-JWT proves the presenter holds the ``cnf`` key the issuer bound to ``sub``, so
    ``sub`` is trustworthy, though it is the issuer's identifier for the holder rather
    than the KB signer's own key thumbprint.

    For the W3C VP formats, the VP proof alone does not bind the credentials it carries
    to the presenter. So when a Credential Query requires **Cryptographic Holder
    Binding** — its ``require_cryptographic_holder_binding``, default ``true`` (OpenID4VP
    1.0 §6.1, §B.1) — every embedded credential must be bound to the authenticated holder,
    or the response is rejected (``ClaimsInvalid``):

    * an **SD-JWT VC** (bare, or in an ``EnvelopedVerifiableCredential``) must carry a
      KB-JWT bound to this exchange (``key_bound=True``); one with no KB-JWT, or no
      ``cnf``, is rejected. The VP signer never stands in for the ``cnf`` key;
    * every other credential (**VC-JWT**, **Data Integrity**) must name the holder as its
      single subject (``sub`` / ``credentialSubject.id``). A bearer credential (no subject
      id), one whose ``credentialSubject`` is an array, or another party's credential is
      rejected. Subject and holder are compared as strings, so the same key under two DID
      methods is two different holders.

    A ``jwt_vc_json`` or ``ldp_vc`` presentation must embed at least one credential,
    whatever the flag.

    To accept a credential the presenter is not bound to — §14.1.1's "the Holder may not
    be the subject of the Credential" — set the flag to ``false`` in that query.
    A non-boolean flag is :class:`VpTokenMalformed`.

    **A bare credential** (§B.1: a Wallet answers a query that waives holder binding with a
    Verifiable Credential, not a presentation). A ``jwt_vc_json`` / ``ldp_vc`` query that sets the
    flag to ``false`` accepts a bare Verifiable Credential *or* a Verifiable Presentation (a
    presentation is what these lanes accepted before). With the flag ``true`` or absent a bare
    credential is :class:`VpTokenMalformed`, on either lane, before anything is verified. The
    bare form is a VC-JWT under ``jwt_vc_json`` and a Data Integrity credential under
    ``ldp_vc`` (any suite :func:`openvc.verify_credential` knows, ``ecdsa-sd-2023`` included),
    verified in full as it is anywhere else; it never reaches the VP-JWT suite, and a bare
    SD-JWT is never accepted under a W3C query. Which shape a value has is decided before
    anything is verified, fail-closed: a JWT is a credential when its payload has a ``vc``
    object and no ``vp``; a JSON object when its ``type`` has ``VerifiableCredential`` and not
    ``VerifiablePresentation``. A value that is positively both, or whose JOSE ``typ``
    (``vc+jwt`` / ``vp+jwt``) contradicts the claim it carries, or an
    ``EnvelopedVerifiableCredential`` (not accepted bare), is :class:`VpTokenMalformed`;
    anything else that is not positively a credential is left to the presentation lane and its
    own typed error. A bare credential has **no audience, nonce, challenge or domain**: a
    VC-JWT that carries an ``aud`` is rejected (``ClaimsInvalid``, RFC 7519 §4.1.3: none can
    name this verifier), and its result is ``holder=None``. Nothing binds it to this exchange,
    so it can be replayed (§14.1.1) and the response carries no ``nonce`` (§5.3): the
    verifier MUST bind request and response with a fresh, high-entropy ``state``, unless the
    Digital Credentials API is used. openvc keeps no state, so **checking ``state`` is the
    caller's job**, as nonce freshness is. *require_holder_binding* cannot be met by a bare
    credential (``ClaimsInvalid``). Status, ``meta.type_values`` and the credential's own
    validity are checked as for any embedded credential.
    The same goes for a Credential Query's ``multiple`` (OpenID4VP 1.0 §6.1, default
    ``false``): each ``vp_token`` value is an array holding exactly one Presentation
    unless the query sets ``"multiple": true`` (§8.1), and a ``multiple`` that is not a
    JSON boolean (``"false"``, ``1``, ``null``, ``[]``, …) is :class:`VpTokenMalformed`,
    naming the query, for every query, answered or not.
    *require_holder_binding* is the caller's own, stricter switch: whatever the query
    says, every embedded credential's subject — an SD-JWT VC's ``sub`` included — must
    be the authenticated holder.

    A KB-JWT that a nested SD-JWT VC does carry must be bound to the **same** audience and
    nonce as the presentation, whatever the flag, or the response is rejected — so a
    nested result's ``key_bound=True`` means bound to this exchange. With the flag
    ``false``, a nested SD-JWT VC without one reports ``key_bound=False``.

    **Completeness** (OpenID4VP 1.0 §6.4.2 and §8.6). With no ``credential_sets``, every
    Credential Query is required and the absence of one raises :class:`VpTokenIncomplete`.
    With ``credential_sets``, every set whose ``required`` is ``true`` or omitted must be
    satisfied: at least one of its ``options`` must have **every** Credential Query id
    answered in the ``vp_token``, else :class:`VpTokenIncomplete` names the set
    (``credential_sets[1]``). A set with ``"required": false`` and a Credential Query that
    no set references may be left out. This is checked on the keys of the ``vp_token``,
    before any Presentation is read, and an empty ``vp_token`` is rejected whatever the
    sets say. Extra answers (several options of a set, a query outside every option) are
    not refused: each Presentation is still verified in full.
    :meth:`VpTokenVerification.for_query` returns ``()`` for a query that was left out, so
    use it to learn which option of a set the wallet answered, and which optional queries
    it chose to answer.

    The shape of ``credential_sets`` is validated for every query set, answered or not,
    after the queries and before any Presentation is read (OpenID4VP 1.0 §6.2): it is a
    non-empty array of objects; each ``options`` is a non-empty array of non-empty arrays
    of ids, every id naming a Credential Query of ``credentials``; ``required``, when
    present, is a JSON boolean. Anything else (``null`` and ``[]`` included) is
    :class:`VpTokenMalformed`, naming the path (``dcql_query.credential_sets[0].options``).
    ``purpose`` and unknown members are not read. The arrays must be Python lists, as for
    ``credentials``: a tuple is :class:`VpTokenMalformed`. Before 1.35.0 any truthy
    ``credential_sets``, whatever it held, switched the completeness check off; ``null``,
    ``[]`` and the other falsy values read as absent, with every query required.
    """
    if not nonce:
        raise ClaimsInvalid("verify_vp_token requires a non-empty nonce")
    accepted_auds = _dc_api_accepted_auds(client_id, expected_origins)

    # Validate the duration knobs once, up front — a NaN leeway would switch every window
    # off, and a lane with no SD-JWT in it would otherwise never look at kb_max_age_s.
    non_negative_seconds(leeway_s, name="leeway_s", error=OpenID4VPError)
    non_negative_seconds(kb_max_age_s, name="kb_max_age_s", error=OpenID4VPError)
    token = _parse_vp_token(vp_token)
    if not token:
        raise VpTokenMalformed("vp_token contains no presentations")
    queries = _index_dcql(dcql_query)
    _check_completeness(token, queries, dcql_query)

    verified: list[VerifiedPresentation] = []
    try:
        for query_id, presentations in token.items():
            query = queries.get(query_id)
            if query is None:
                raise VpTokenMalformed(
                    f"vp_token key {query_id!r} is not a Credential Query id in the DCQL query")
            for presentation in _presentation_list(query_id, query, presentations):
                verified.append(_verify_one(
                    query_id, query, presentation,
                    nonce=nonce, client_id=client_id, accepted_auds=accepted_auds,
                    expected_origins=expected_origins, trust_anchors=trust_anchors,
                    mdoc_jwk_thumbprint=mdoc_jwk_thumbprint,
                    resolver=resolver, now=now, leeway_s=leeway_s, extra_contexts=extra_contexts,
                    require_holder_binding=require_holder_binding,
                    jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
                    x5c_trust_anchors=x5c_trust_anchors,
                    resolve_status_list=resolve_status_list,
                    resolve_status_list_token=resolve_status_list_token,
                    require_status=require_status, kb_max_age_s=kb_max_age_s))
    except RecursionError as exc:       # backstop: a value nested past the stack
        raise VpTokenMalformed("vp_token is nested too deeply to verify") from exc
    return VpTokenVerification(presentations=tuple(verified))


def verify_encrypted_vp_response(
    response: str,
    *,
    key: "KeyAgreementKey",
    dcql_query: Mapping[str, Any],
    nonce: str,
    client_id: str | None = None,
    expected_origins: Sequence[str] | None = None,
    trust_anchors: Sequence[Any] | None = None,
    mdoc_jwk_thumbprint: bytes | None = None,
    resolver: Any = None,
    now: datetime | None = None,
    leeway_s: int = DEFAULT_LEEWAY_S,
    extra_contexts: Mapping[str, dict] | None = None,
    require_holder_binding: bool = False,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
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
        payload = _json.loads(plaintext)
    except (ValueError, RecursionError) as exc:
        raise VpTokenMalformed(f"decrypted response is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping) or "vp_token" not in payload:
        raise VpTokenMalformed("decrypted response has no vp_token member")
    return verify_vp_token(
        payload["vp_token"], dcql_query=dcql_query, nonce=nonce, client_id=client_id,
        kb_max_age_s=kb_max_age_s,
        expected_origins=expected_origins, trust_anchors=trust_anchors,
        mdoc_jwk_thumbprint=mdoc_jwk_thumbprint, resolver=resolver, now=now,
        leeway_s=leeway_s, extra_contexts=extra_contexts,
        require_holder_binding=require_holder_binding,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors,
        resolve_status_list=resolve_status_list,
        resolve_status_list_token=resolve_status_list_token,
        require_status=require_status)


def _parse_vp_token(vp_token: Mapping[str, Any] | str) -> Mapping[str, Any]:
    if isinstance(vp_token, str):
        try:
            vp_token = _json.loads(vp_token)
        except (ValueError, RecursionError) as exc:
            raise VpTokenMalformed(f"vp_token is not valid JSON: {exc}") from exc
    if not isinstance(vp_token, Mapping):
        raise VpTokenMalformed(
            "vp_token must be a JSON object keyed by Credential Query id")
    # a vp_token handed over already parsed skips the bounded loader: same bound
    if _json.nesting_exceeds(dict(vp_token)):
        raise VpTokenMalformed(f"vp_token is nested deeper than {_json.MAX_DEPTH} levels")
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
        # A malformed flag fails safe: coercing it would let bool(None) / bool(0) opt the
        # query out of holder binding, and would let "false" / 1 open a query to several
        # Presentations (#268). Both are checked for EVERY query, answered or not; a bool
        # is exact (0, 1 and 1.0 are not JSON booleans). _presentation_list reads
        # ``multiple`` after this, so it only ever sees a bool. A credential set's
        # ``required`` is held to the same rule, after the walk (_check_credential_sets).
        if not isinstance(entry.get("require_cryptographic_holder_binding", True), bool):
            raise VpTokenMalformed(
                f"Credential Query {query_id!r}: require_cryptographic_holder_binding "
                f"must be a boolean")
        if not isinstance(entry.get("multiple", False), bool):
            raise VpTokenMalformed(
                f"Credential Query {query_id!r}: multiple must be a boolean")
        _check_constraint(query_id, entry, fmt)
        queries[query_id] = entry
    # After the query walk (the ids are needed, and a query's own shape error is reported
    # first) and before any Presentation is read. Only a PRESENT key is checked: an absent
    # one means "every query is required", but ``null`` and ``[]`` are never "absent" (#284).
    if "credential_sets" in dcql_query:
        _check_credential_sets(dcql_query["credential_sets"], queries)
    return queries


def _check_credential_sets(value: Any, queries: Mapping[str, Any]) -> None:
    # OpenID4VP 1.0 §6.2: ``credential_sets`` is a non-empty array of objects. Each has a
    # REQUIRED ``options`` (a non-empty array of non-empty arrays of Credential Query ids,
    # each an entry of ``credentials``) and an OPTIONAL boolean ``required`` (default
    # true). It was read once, by truthiness, as the switch that turned completeness off
    # (#284). Every set is checked, answered or not; ``purpose``, unknown members and
    # duplicate ids inside one option are not read. Messages name the path, never the
    # value; an unknown id is named, like a query id elsewhere, cut by safe_repr.
    if not isinstance(value, list) or not value:
        raise VpTokenMalformed("dcql_query.credential_sets must be a non-empty array")
    for index, entry in enumerate(value):
        where = f"dcql_query.credential_sets[{index}]"
        if not isinstance(entry, Mapping):
            raise VpTokenMalformed(f"{where} must be an object")
        options = entry.get("options")
        if not isinstance(options, list) or not options:
            raise VpTokenMalformed(f"{where}.options must be a non-empty array")
        for position, option in enumerate(options):
            if not isinstance(option, list) or not option:
                raise VpTokenMalformed(
                    f"{where}.options[{position}] must be a non-empty array of "
                    f"Credential Query ids")
            for query_id in option:
                if not isinstance(query_id, str):
                    raise VpTokenMalformed(
                        f"{where}.options[{position}] must hold only Credential Query "
                        f"ids (strings)")
                if query_id not in queries:
                    raise VpTokenMalformed(
                        f"{where}.options[{position}] names Credential Query "
                        f"{safe_repr(query_id)}, which is not in dcql_query.credentials")
        # A bool is exact: 0, 1 and 1.0 are not JSON booleans, and "false" is truthy.
        if not isinstance(entry.get("required", True), bool):
            raise VpTokenMalformed(f"{where}.required must be a boolean")


def _check_constraint(query_id: str, query: Mapping[str, Any], fmt: str) -> None:
    # Validate a Credential Query's type constraint (its ``meta``) up front, for EVERY
    # query, answered or not (#254), so a malformed one fails the same way whatever the
    # wallet sent and whichever alternative of ``credential_sets`` it answered. The
    # readers are pure and cheap: the verifiers re-read the constraint when they use it.
    # A format openvc does not know is left alone (its ``meta`` is not read, as before),
    # and so are the keys of another format: each format reads only its own.
    if fmt == FORMAT_SD_JWT_VC:
        _vct_values(query_id, query)
    elif fmt == FORMAT_MSO_MDOC:
        _mdoc_doctype_value(query_id, query)
    elif fmt in (FORMAT_JWT_VC, FORMAT_LDP_VC):
        _type_values(query_id, query)


def _check_completeness(
    token: Mapping[str, Any], queries: Mapping[str, Any],
    dcql_query: Mapping[str, Any],
) -> None:
    # OpenID4VP 1.0 §6.4.2 says what the Verifier requests, and §8.6 (the last step) makes
    # "the set of Presentations returned satisfies all requirements" a reason to reject.
    # It runs on the keys of the vp_token, before any Presentation is read: openvc rejects
    # the whole response when any Presentation fails, so a key that is present and then
    # fails never leaves a set satisfied. ``_index_dcql`` has already validated the shape
    # (#284): the key is absent, or a non-empty list of objects whose ``options`` are
    # non-empty lists of known query ids and whose ``required`` is a bool.
    if "credential_sets" not in dcql_query:
        # No credential_sets: the Verifier requests every Credential Query.
        missing = [qid for qid in queries if qid not in token]
        if missing:
            raise VpTokenIncomplete(
                f"vp_token is missing required Credential Query id(s): {sorted(missing)}")
        return
    # With credential_sets: every set whose ``required`` is true or omitted (default true,
    # §6.2) must be satisfied by ONE of its options, every id of which is answered. A set
    # with ``required: false`` is not checked, and a query that no set references is not
    # requested (§6.4.2 read literally), so either may be left out. Extra answers are not
    # refused here: each Presentation sent is still verified in full.
    for index, entry in enumerate(dcql_query["credential_sets"]):
        if not entry.get("required", True):
            continue
        lacking = [[qid for qid in option if qid not in token] for option in entry["options"]]
        if all(lacking):                  # no option is answered in full
            closest = min(range(len(lacking)), key=lambda i: len(lacking[i]))
            raise VpTokenIncomplete(
                f"vp_token does not satisfy credential_sets[{index}]: no option is "
                f"answered in full; the closest is options[{closest}], which lacks "
                f"Credential Query id(s) {sorted(lacking[closest])}")


def _presentation_list(query_id: str, query: Mapping[str, Any], value: Any) -> list[Any]:
    # OpenID4VP 1.0 §8.1: the value is ALWAYS an array; length 1 unless multiple:true.
    # ``multiple`` is a bool here: _index_dcql rejected any other type (#268).
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


def _b64url_json(segment: str) -> Mapping[str, Any]:
    obj = _json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    return obj if isinstance(obj, Mapping) else {}


def _peek_audience(fmt: str, presentation: Any) -> Any:
    """The UNVERIFIED audience the presentation claims — the KB-JWT / VP-JWT ``aud`` or the
    LDP-VP proof ``domain``. Used only to pick which expected origin to enforce; the value
    lives in the signed payload, so the subsequent signature check binds it (peeking it
    first cannot change what was signed)."""
    try:
        if fmt == FORMAT_SD_JWT_VC and isinstance(presentation, str):
            kb = presentation.rsplit("~", 1)[-1]           # the KB-JWT is the final segment
            return _b64url_json(kb.split(".")[1]).get("aud") if kb else None
        if fmt == FORMAT_JWT_VC and isinstance(presentation, str):
            return _b64url_json(presentation.split(".")[1]).get("aud")
        if fmt == FORMAT_LDP_VC and isinstance(presentation, Mapping):
            proof = presentation.get("proof")
            proof = proof[0] if isinstance(proof, list) and proof else proof
            return proof.get("domain") if isinstance(proof, Mapping) else None
    except (ValueError, KeyError, IndexError, TypeError, RecursionError, json.JSONDecodeError):
        # RecursionError: a hostile deeply-nested JSON payload — the peek runs before any
        # signature check, so this must fail closed (-> None -> ClaimsInvalid), never escape
        # as a bare exception past the OpenvcError family (matches _parse_vp_token's guard).
        return None
    return None


def _effective_audience(
    fmt: str, presentation: Any, client_id: str | None, accepted_auds: frozenset[str] | None,
) -> str:
    """The audience to enforce for this presentation: *client_id* verbatim (redirect /
    ``direct_post`` flow), or — over the W3C Digital Credentials API — the
    ``origin:<origin>`` the presentation is bound to, required to be one of *accepted_auds*
    (the ``origin:``-prefixed *expected_origins*). Per OpenID4VP 1.0 Appendix A the DC API
    audience is ALWAYS the calling origin, never the client_id."""
    if client_id is not None:
        return client_id
    assert accepted_auds is not None
    aud = _peek_audience(fmt, presentation)
    for candidate in (aud if isinstance(aud, list) else [aud]):
        if isinstance(candidate, str) and candidate in accepted_auds:
            return candidate
    raise ClaimsInvalid(
        f"DC API presentation audience {safe_repr(aud)} is not one of the expected origins "
        f"(need one of {sorted(accepted_auds)})")


def _verify_one(
    query_id: str, query: Mapping[str, Any], presentation: Any, *,
    nonce: str, client_id: str | None, accepted_auds: frozenset[str] | None,
    expected_origins: Sequence[str] | None, trust_anchors: Sequence[Any] | None,
    mdoc_jwk_thumbprint: bytes | None,
    resolver: Any, now: datetime | None, leeway_s: int,
    extra_contexts: Mapping[str, dict] | None, require_holder_binding: bool,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
) -> VerifiedPresentation:
    fmt = query["format"]
    # mso_mdoc binds the holder through DeviceAuth over a SessionTranscript, not a
    # peekable `aud`, so it is handled before the JOSE / LDP audience is computed.
    if fmt == FORMAT_MSO_MDOC:
        return _verify_mso_mdoc(
            query_id, query, presentation, nonce=nonce, expected_origins=expected_origins,
            trust_anchors=trust_anchors, now=now, leeway_s=leeway_s,
            jwk_thumbprint=mdoc_jwk_thumbprint)
    # DCQL meta.type_values (the W3C formats) and meta.vct_values (dc+sd-jwt) are read
    # before anything is verified. _index_dcql has already validated every query's
    # constraint, answered or not (#254), so a malformed one never reaches this point:
    # these are re-reads of a checked value, kept next to their use. What is new here is
    # the pyld requirement, which only a query that is actually answered has to meet.
    type_values = (_type_values(query_id, query)
                   if fmt in (FORMAT_JWT_VC, FORMAT_LDP_VC) else None)
    if type_values is not None:
        _require_pyld(query_id)
    vct_values = _vct_values(query_id, query) if fmt == FORMAT_SD_JWT_VC else None
    # Cryptographic Holder Binding is required unless the query opted out (OpenID4VP 1.0
    # §6.1, default true); _index_dcql has already checked that the flag is a boolean.
    require_binding = query.get("require_cryptographic_holder_binding", True)
    # A W3C query is answered with a Verifiable Presentation, or — when it opted out of
    # holder binding — with a bare Verifiable Credential (§B.1, #204). Decide which BEFORE
    # the audience is read: a bare credential carries no aud / domain, so over the DC API
    # it would otherwise die in _effective_audience, and under flag true it would reach
    # the VP-JWT suite as if it were a VP.
    if fmt in (FORMAT_JWT_VC, FORMAT_LDP_VC) and _w3c_shape(
            query_id, fmt, presentation) == _SHAPE_VC:
        if require_binding:
            raise VpTokenMalformed(
                f"Credential Query {query_id!r} requires cryptographic holder binding "
                f"(require_cryptographic_holder_binding is true or absent), so its "
                f"{fmt} answer must be a Verifiable Presentation; a bare Verifiable "
                f"Credential is accepted only when the query sets it to false")
        return _verify_bare_w3c_vc(
            query_id, fmt, presentation, type_values=type_values,
            resolver=resolver, now=now, leeway_s=leeway_s, extra_contexts=extra_contexts,
            require_holder_binding=require_holder_binding,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            require_status=require_status, kb_max_age_s=kb_max_age_s)
    # The audience is the client_id (redirect flow) or the DC-API calling origin.
    aud = _effective_audience(fmt, presentation, client_id, accepted_auds)
    if fmt == FORMAT_SD_JWT_VC:
        return _verify_sd_jwt_vc(
            query_id, vct_values, presentation, require_binding=require_binding,
            nonce=nonce, client_id=aud, resolver=resolver, now=now, leeway_s=leeway_s,
            kb_max_age_s=kb_max_age_s,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            require_status=require_status)
    if fmt == FORMAT_JWT_VC:
        return _verify_jwt_vp(
            query_id, presentation, require_binding=require_binding,
            nonce=nonce, client_id=aud, resolver=resolver, now=now, leeway_s=leeway_s,
            kb_max_age_s=kb_max_age_s, type_values=type_values,
            extra_contexts=extra_contexts,
            require_holder_binding=require_holder_binding,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            require_status=require_status)
    if fmt == FORMAT_LDP_VC:
        return _verify_ldp_vp(
            query_id, presentation, require_binding=require_binding,
            nonce=nonce, client_id=aud, resolver=resolver,
            now=now, leeway_s=leeway_s, extra_contexts=extra_contexts,
            kb_max_age_s=kb_max_age_s, type_values=type_values,
            require_holder_binding=require_holder_binding,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            require_status=require_status)
    raise UnsupportedPresentationFormat(
        f"Credential Query {query_id!r} has unknown format {fmt!r}")


def dcapi_session_transcript(
    origin: str, nonce: str, *, jwk_thumbprint: bytes | None = None,
) -> bytes:
    """Build the OpenID4VP-over-Digital-Credentials-API ``SessionTranscript`` (CBOR bytes)
    that an mdoc ``DeviceAuth`` is bound to (OpenID4VP 1.0 Appendix B / ISO 18013-7):
    ``[null, null, ["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce, jwk_thumbprint]))]]``.

    *origin* is the calling web origin (e.g. ``https://verifier.example``), *nonce* the
    Authorization Request nonce, and *jwk_thumbprint* the SHA-256 JWK thumbprint of the
    verifier's response-encryption key (``None`` → CBOR ``null``, for an unencrypted
    response) — compute it with :func:`openvc.keys.jwk_thumbprint_bytes`, which returns
    the raw digest this expects.
    **Experimental**: track ISO 18013-7 / OpenID4VP as the handover finalises."""
    from . import cbor

    handover_info = cbor.encode([origin, nonce, jwk_thumbprint])
    handover = ["OpenID4VPDCAPIHandover", hashlib.sha256(handover_info).digest()]
    return cbor.encode([None, None, handover])


def _b64url_to_bytes(query_id: str, value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:            # binascii.Error is a ValueError
        raise VpTokenMalformed(
            f"the {FORMAT_MSO_MDOC} Presentation for {query_id!r} is not valid "
            f"base64url: {exc}") from exc


def _mdoc_doctype_value(query_id: str, query: Mapping[str, Any]) -> str | None:
    # DCQL meta.doctype_value constrains the acceptable mdoc docType for an mso_mdoc query
    # (OpenID4VP DCQL §6.3.2) — the mdoc analogue of SD-JWT's meta.vct_values. If the query
    # named it, the presented docType MUST equal it (the "right credential"). Absent means
    # no constraint; a present value that is not a non-empty string (an explicit null
    # included) fails safe rather than silently widening.
    meta = _dcql_meta(query_id, query)
    if "doctype_value" not in meta:
        return None
    doctype = meta["doctype_value"]
    if not isinstance(doctype, str) or not doctype:
        raise VpTokenMalformed(
            f"Credential Query {query_id!r}: meta.doctype_value must be a non-empty string")
    return doctype


def _verify_mso_mdoc(
    query_id: str, query: Mapping[str, Any], presentation: Any, *,
    nonce: str, expected_origins: Sequence[str] | None,
    trust_anchors: Sequence[Any] | None, now: datetime | None, leeway_s: int,
    jwk_thumbprint: bytes | None,
) -> VerifiedPresentation:
    from . import mdoc

    if expected_origins is None:
        raise UnsupportedPresentationFormat(
            f"Credential Query {query_id!r} format {FORMAT_MSO_MDOC!r} is only wired for "
            f"the W3C Digital Credentials API flow — pass expected_origins")
    if trust_anchors is None:
        raise ClaimsInvalid(
            "verifying an mso_mdoc needs trust_anchors (the IACA root certificates)")
    if not isinstance(presentation, str):
        raise VpTokenMalformed(
            f"an {FORMAT_MSO_MDOC} Presentation for {query_id!r} must be a base64url "
            f"string (the DeviceResponse)")
    # Re-read of a constraint _index_dcql already validated for every query (#254).
    expected_doc_type = _mdoc_doctype_value(query_id, query)
    device_response = _b64url_to_bytes(query_id, presentation)

    # The DeviceAuth binds to exactly one origin's SessionTranscript; statelessly we do
    # not know which of expected_origins served this request, so try each and accept the
    # one whose holder binding verifies. Only a DeviceAuth failure advances to the next
    # candidate — an issuer-seal / digest / validity failure rejects immediately.
    last_error: Exception | None = None
    for origin in expected_origins:
        transcript = dcapi_session_transcript(origin, nonce, jwk_thumbprint=jwk_thumbprint)
        try:
            documents = mdoc.verify_device_response(
                device_response, trust_anchors=trust_anchors,
                session_transcript=transcript, now=now, leeway_s=leeway_s,
                expected_doc_type=expected_doc_type)
        except mdoc.MdocDeviceAuthError as exc:
            last_error = exc
            continue
        return VerifiedPresentation(
            query_id=query_id, format=FORMAT_MSO_MDOC, holder=None,
            credentials=tuple(documents), raw=documents)
    assert last_error is not None                     # expected_origins is non-empty here
    raise last_error


def _verify_sd_jwt_vc(
    query_id: str, vct_values: list[str] | None, presentation: Any, *, require_binding: bool,
    nonce: str, client_id: str, resolver: Any, now: datetime | None, leeway_s: int,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
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
    policy = VerificationPolicy(
        audience=client_id, nonce=nonce, require_key_binding=require_binding,
        require_status=require_status, now=now, leeway_s=leeway_s,
        kb_max_age_s=kb_max_age_s)
    result = verify_credential(
        presentation, policy=policy, resolver=resolver,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors,
        resolve_status_list=resolve_status_list,
        resolve_status_list_token=resolve_status_list_token)
    if result.format != _PIPELINE_SD_JWT:            # defence in depth vs re-detection
        raise VpTokenMalformed(
            f"Presentation for {query_id!r} did not verify as an SD-JWT VC "
            f"(got {result.format!r})")
    # The pipeline names every SD-JWT "sd-jwt-vc", a W3C VCDM credential secured as
    # `vc+sd-jwt`, as the draft-era `vc+ld+json+sd-jwt` or with no `typ` (VC-JOSE-COSE)
    # included. This format is the IETF SD-JWT VC, whose issuer JWT is typed `dc+sd-jwt`
    # (draft-19 §2.2.1), the same string as the format (#272).
    issuer_typ = getattr(result.raw, "typ", None)
    if issuer_typ != FORMAT_SD_JWT_VC:
        raise VpTokenMalformed(
            f"a {FORMAT_SD_JWT_VC} Presentation for {query_id!r} must be an IETF SD-JWT VC "
            f"(issuer JWT typ {FORMAT_SD_JWT_VC!r}, got {safe_repr(issuer_typ)})")
    _check_vct(query_id, vct_values, getattr(result.raw, "vct", None))
    holder = result.subject
    return VerifiedPresentation(
        query_id=query_id, format=FORMAT_SD_JWT_VC, holder=holder,
        credentials=(result,), raw=result.raw)


def _verify_jwt_vp(
    query_id: str, presentation: Any, *, require_binding: bool,
    nonce: str, client_id: str, resolver: Any, now: datetime | None, leeway_s: int,
    require_holder_binding: bool = False,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
    type_values: list[list[str]] | None = None,
    extra_contexts: Mapping[str, dict] | None = None,
) -> VerifiedPresentation:
    from .proof.vp_jwt import VpJwtProofSuite
    from .verify import VerificationPolicy

    if not isinstance(presentation, str):
        raise VpTokenMalformed(
            f"a {FORMAT_JWT_VC} Presentation for {query_id!r} must be a compact JWT string")
    # Nested SD-JWT VCs are held to the caller's KB-JWT window too, not the default, and
    # need a KB-JWT at all when the query requires holder binding.
    policy = VerificationPolicy(require_status=require_status, now=now, leeway_s=leeway_s,
                                kb_max_age_s=kb_max_age_s, require_key_binding=require_binding)
    # resolver mode authenticates the holder from `iss`, so require_holder_binding binds
    # subject==holder without needing expected_holder (VP-JWT enforces that invariant).
    # The suite also binds any nested SD-JWT's KB-JWT to this same aud + nonce.
    verified = VpJwtProofSuite(leeway_s=leeway_s).verify(
        presentation, audience=client_id, nonce=nonce, resolver=resolver,
        require_holder_binding=require_holder_binding, policy=policy,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors,
        resolve_status_list=resolve_status_list,
        resolve_status_list_token=resolve_status_list_token)
    # A presentation answering a Credential Query must carry at least one credential
    # (as the ldp_vc lane's _embedded_vcs requires). The suite accepts a credential-less
    # VP — VCDM allows one, e.g. DID Auth — so the OpenID4VP rule is enforced here; an
    # empty one would also meet the holder binding below vacuously.
    if not verified.credentials:
        raise VpTokenMalformed(
            f"the {FORMAT_JWT_VC} Presentation for {query_id!r} embeds no "
            f"verifiableCredential")
    if require_binding:
        _check_holder_bound(query_id, verified.credentials, verified.holder)
    _check_type_values(query_id, type_values, verified.credentials, extra_contexts)
    return VerifiedPresentation(
        query_id=query_id, format=FORMAT_JWT_VC, holder=verified.holder,
        credentials=tuple(verified.credentials), raw=verified)


def _verify_ldp_vp(
    query_id: str, presentation: Any, *, require_binding: bool,
    nonce: str, client_id: str, resolver: Any, now: datetime | None, leeway_s: int,
    extra_contexts: Mapping[str, dict] | None, require_holder_binding: bool,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
    type_values: list[list[str]] | None = None,
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
    # a JSON array/object cryptosuite is unhashable: type-check before `in frozenset`
    if not isinstance(cryptosuite, str) or cryptosuite not in _LDP_VP_CRYPTOSUITES:
        raise UnsupportedPresentationFormat(
            f"the {FORMAT_LDP_VC} Presentation for {query_id!r} uses an unsupported "
            f"Data Integrity cryptosuite {safe_repr(cryptosuite)}")

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
    # Nested SD-JWT VCs are held to the caller's KB-JWT window too, not the default, and
    # need a KB-JWT at all when the query requires holder binding.
    policy = VerificationPolicy(require_status=require_status, now=now, leeway_s=leeway_s,
                                kb_max_age_s=kb_max_age_s, require_key_binding=require_binding)
    credentials = tuple(
        verify_credential(
            vc, policy=policy, resolver=resolver, extra_contexts=extra_contexts,
            jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
            x5c_trust_anchors=x5c_trust_anchors,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            # a nested SD-JWT's KB-JWT is bound to this VP's domain (aud) + challenge
            _kb_binding=(client_id, nonce))
        for vc in _embedded_vcs(query_id, presentation))

    if require_binding:
        _check_holder_bound(query_id, credentials, holder)
    # Optional subject binding: require each embedded credential to have been issued
    # to the authenticated holder (the presenter owns what they present).
    if require_holder_binding:
        for result in credentials:
            if not result.subject or result.subject != holder:
                raise ClaimsInvalid(
                    f"credential subject {result.subject!r} is not the authenticated "
                    f"holder {holder!r} (require_holder_binding)")

    _check_type_values(query_id, type_values, credentials, extra_contexts)
    return VerifiedPresentation(
        query_id=query_id, format=FORMAT_LDP_VC, holder=holder,
        credentials=credentials, raw=verified_vp)


def _w3c_shape(query_id: str, fmt: str, presentation: Any) -> str:
    """Whether a ``jwt_vc_json`` / ``ldp_vc`` answer is a bare Verifiable Credential
    (``"vc"``) or goes to the Presentation lane (``"vp"``). OpenID4VP 1.0 §B.1: a Wallet
    answers a query that requires holder binding with a Verifiable Presentation and one
    that does not with a Verifiable Credential (#204).

    This reads attacker-controlled bytes before any signature is checked, so it only
    ever *routes*: the route it picks verifies everything about its own shape, and the
    VP route is the strict one (aud + nonce / domain + challenge). A value is a bare
    credential only on positive evidence. Anything else, one that does not parse
    included, is left to the VP lane and its own typed error. A value that is positively
    both, or whose declared type contradicts its content, is refused here
    (:class:`VpTokenMalformed`): this layer does not guess which one it is.

    * ``jwt_vc_json`` (a compact JWS, no ``~``): the **payload claim** decides. A ``vc``
      object and no ``vp`` is a credential, as OpenID4VP's own §B.1.3.1 example shows,
      and a ``vp`` and no ``vc`` is a presentation: the two claims are what
      ``VcJwtProofSuite`` and ``VpJwtProofSuite`` read. Both is ambiguous. The JOSE
      ``typ`` is not the signal: VC-JOSE-COSE says it SHOULD be ``vc+jwt`` / ``vp+jwt``
      and openvc signs both as ``JWT``, so an absent or generic one proves nothing. It is a
      cross-check only: a ``typ`` naming the other kind than the claim is a contradiction.
    * ``ldp_vc`` (a JSON object): the ``type`` decides. ``VerifiableCredential`` without
      ``VerifiablePresentation`` is a credential; with it, ambiguous.
      A ``VerifiablePresentation``-typed object is always a presentation, whatever else
      it lists. An ``EnvelopedVerifiableCredential`` that is not typed as one is refused:
      OpenID4VP §B.1 does not mention it for these formats, so it is not accepted as a
      bare credential."""
    if fmt == FORMAT_JWT_VC:
        return _jwt_shape(query_id, presentation)
    return _ldp_shape(query_id, presentation)


def _jwt_shape(query_id: str, presentation: Any) -> str:
    peeked = _peek_jws(presentation)
    if peeked is None:
        return _SHAPE_VP
    header, payload = peeked
    has_vp, has_vc = "vp" in payload, "vc" in payload
    if has_vp and has_vc:
        raise VpTokenMalformed(
            f"the {FORMAT_JWT_VC} Presentation for {query_id!r} carries both a `vp` and a "
            f"`vc` claim, so it is not decidably a presentation or a credential")
    if not has_vp and not isinstance(payload.get("vc"), dict):
        return _SHAPE_VP            # neither claim, or a `vc` that is no object: no evidence
    shape = _SHAPE_VP if has_vp else _SHAPE_VC
    typed = _jwt_typ_kind(header)
    if typed is not None and typed != shape:
        raise VpTokenMalformed(
            f"the {FORMAT_JWT_VC} Presentation for {query_id!r} is typed "
            f"{safe_repr(header.get('typ'))} but carries a "
            f"{'`vp`' if has_vp else '`vc`'} claim")
    return shape


def _ldp_shape(query_id: str, presentation: Any) -> str:
    if not isinstance(presentation, Mapping):
        return _SHAPE_VP            # a string or a number: the ldp_vc lane's own error
    types = presentation.get("type")
    type_list = ([types] if isinstance(types, str)
                 else types if isinstance(types, list) else [])
    is_vp = "VerifiablePresentation" in type_list
    is_vc = "VerifiableCredential" in type_list
    if is_vp and is_vc:
        raise VpTokenMalformed(
            f"an {FORMAT_LDP_VC} Presentation for {query_id!r} is typed both "
            f"VerifiablePresentation and VerifiableCredential, so it is not decidably "
            f"a presentation or a credential")
    if is_vp:
        # A presentation, whatever else its type lists (an extra EnvelopedVerifiableCredential
        # included): the VP lane decides, as it did before the bare route existed.
        return _SHAPE_VP
    if "EnvelopedVerifiableCredential" in type_list:
        raise VpTokenMalformed(
            f"an {FORMAT_LDP_VC} Presentation for {query_id!r} is an "
            f"EnvelopedVerifiableCredential, which is not accepted: answer with a "
            f"VerifiablePresentation or a Data Integrity VerifiableCredential")
    return _SHAPE_VC if is_vc else _SHAPE_VP


def _peek_jws(value: Any) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The UNVERIFIED header and payload of a compact JWS, or ``None`` unless *value* is a
    string of three dot-separated segments, with no ``~`` (an SD-JWT is never routed
    here), whose first two decode to JSON objects. Used only to route, like
    :func:`_peek_audience`: a hostile value that fails to parse falls through to the
    lane that rejects it with its own typed error, never to an acceptance."""
    if not isinstance(value, str) or "~" in value:
        return None
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        header, payload = (
            _json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            for part in parts[:2])
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _jwt_typ_kind(header: Mapping[str, Any]) -> str | None:
    # The kind a JOSE ``typ`` declares: VC-JOSE-COSE's ``vc+jwt`` / ``vp+jwt`` (the media
    # type, with or without the ``application/`` prefix RFC 7515 §4.1.9 allows). Anything
    # else, ``JWT`` included, declares nothing.
    typ = header.get("typ")
    if not isinstance(typ, str):
        return None
    media = typ.lower()
    if media.startswith("application/"):
        media = media[len("application/"):]
    return {"vc+jwt": _SHAPE_VC, "vp+jwt": _SHAPE_VP}.get(media)


def _verify_bare_w3c_vc(
    query_id: str, fmt: str, presentation: Any, *,
    type_values: list[list[str]] | None, resolver: Any, now: datetime | None,
    leeway_s: int, extra_contexts: Mapping[str, dict] | None, require_holder_binding: bool,
    jwt_vc_issuer_fetch: Any = None,
    x5c_trust_anchors: Any = None,
    resolve_status_list: Any = None,
    resolve_status_list_token: Any = None,
    require_status: bool = False,
    kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
) -> VerifiedPresentation:
    from .verify import VerificationPolicy, verify_credential

    # The caller's own switch: every credential's subject must be the authenticated
    # holder. A bare credential has no holder, so it cannot meet it — fail closed.
    if require_holder_binding:
        raise ClaimsInvalid(
            f"Credential Query {query_id!r}: a bare credential has no authenticated "
            f"holder, so it cannot meet require_holder_binding")
    # No audience and no nonce: nothing in a bare credential is bound to this exchange, and
    # the response carries no nonce to bind it to (OpenID4VP 1.0 §5.3). Keeping audience
    # None also keeps RFC 7519 §4.1.3 closed: a VC-JWT that is restricted to an audience
    # (carries `aud`) is rejected, since no audience can name this verifier.
    policy = VerificationPolicy(
        require_status=require_status, now=now, leeway_s=leeway_s, kb_max_age_s=kb_max_age_s)
    result = verify_credential(
        presentation if fmt == FORMAT_JWT_VC else dict(presentation),
        policy=policy, resolver=resolver, extra_contexts=extra_contexts,
        jwt_vc_issuer_fetch=jwt_vc_issuer_fetch,
        x5c_trust_anchors=x5c_trust_anchors,
        resolve_status_list=resolve_status_list,
        resolve_status_list_token=resolve_status_list_token)
    _check_bare_format(query_id, fmt, result)
    _check_type_values(query_id, type_values, (result,), extra_contexts)
    return VerifiedPresentation(
        query_id=query_id, format=fmt, holder=None, credentials=(result,), raw=result.raw)


def _check_bare_format(query_id: str, fmt: str, result: Any) -> None:
    # Pin the query's format to what verified, as _verify_sd_jwt_vc does. verify_credential
    # re-detects the format from the value; a bare value under jwt_vc_json must have
    # verified as a VC-JWT (never an SD-JWT or an enveloped credential), and under ldp_vc
    # as a Data Integrity credential. Defence in depth: _w3c_shape already keeps the other
    # shapes out.
    from .verify import (
        FORMAT_DI_ECDSA_JCS,
        FORMAT_DI_ECDSA_RDFC,
        FORMAT_DI_ECDSA_SD,
        FORMAT_DI_EDDSA,
        FORMAT_DI_EDDSA_JCS,
        FORMAT_VC_JWT,
    )

    expected = ((FORMAT_VC_JWT,) if fmt == FORMAT_JWT_VC else (
        FORMAT_DI_EDDSA, FORMAT_DI_EDDSA_JCS, FORMAT_DI_ECDSA_RDFC, FORMAT_DI_ECDSA_JCS,
        FORMAT_DI_ECDSA_SD))
    if getattr(result, "format", None) not in expected:
        raise VpTokenMalformed(
            f"the bare credential for {query_id!r} did not verify as a {fmt} credential "
            f"(got {safe_repr(getattr(result, 'format', None))})")


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


def _check_holder_bound(query_id: str, credentials: Sequence[Any], holder: str | None) -> None:
    # Cryptographic Holder Binding for the W3C VP formats (OpenID4VP 1.0 §2, §B.1): the VP
    # proof authenticates *holder*, which binds a credential only if that credential is
    # bound to the same holder. An SD-JWT VC is bound by its `cnf` key, so it needs a
    # KB-JWT bound to this exchange (the suite already required one) — the VP signer never
    # stands in for that key. Any other format names its holder as its single subject — a
    # credentialSubject array has none (a VC-JWT would otherwise report its `sub` even when
    # the array names someone else). Anything that is not an SD-JWT takes the subject
    # rule, so an unforeseen format fails closed.
    from .verify import FORMAT_SD_JWT_VC as _PIPELINE_SD_JWT

    for result in credentials:
        if result.format == _PIPELINE_SD_JWT:
            if result.key_bound is not True:            # defence in depth vs the policy
                raise ClaimsInvalid(
                    f"Credential Query {query_id!r} requires cryptographic holder binding: "
                    f"a nested SD-JWT VC has no Key Binding JWT bound to this presentation")
            continue
        credential = result.credential
        if isinstance(credential, Mapping) and isinstance(
                credential.get("credentialSubject"), list):
            raise ClaimsInvalid(
                f"Credential Query {query_id!r} requires cryptographic holder binding: a "
                f"credential with a credentialSubject array has no single subject to bind")
        if not holder or not result.subject or result.subject != holder:
            raise ClaimsInvalid(
                f"Credential Query {query_id!r} requires cryptographic holder binding: "
                f"credential subject {result.subject!r} is not the authenticated holder "
                f"{holder!r}")


def _dcql_meta(query_id: str, query: Mapping[str, Any]) -> Mapping[str, Any]:
    # The DCQL ``meta`` of a Credential Query, for the type constraints read from it
    # (vct_values, doctype_value, type_values). An absent ``meta`` is the empty object: no
    # constraint. A ``meta`` that is present but not a JSON object (null, an array, a
    # string) fails safe (VpTokenMalformed) instead of reading as "no constraint" and
    # widening the query to any type. One reader for all three formats, so they cannot
    # drift apart.
    if "meta" not in query:
        return {}
    meta = query["meta"]
    if not isinstance(meta, Mapping):
        raise VpTokenMalformed(f"Credential Query {query_id!r}: meta must be a JSON object")
    return meta


def _vct_values(query_id: str, query: Mapping[str, Any]) -> list[str] | None:
    # DCQL meta.vct_values constrains the acceptable SD-JWT VC type(s) (§6.3.1). Absent
    # means no constraint; a present value that is not a non-empty array of strings (an
    # explicit null included) fails safe (VpTokenMalformed) rather than silently widening.
    meta = _dcql_meta(query_id, query)
    if "vct_values" not in meta:
        return None
    vct_values = meta["vct_values"]
    if (not isinstance(vct_values, list) or not vct_values
            or not all(isinstance(v, str) for v in vct_values)):
        raise VpTokenMalformed(
            f"Credential Query {query_id!r}: meta.vct_values must be a non-empty array "
            f"of strings")
    return vct_values


def _check_vct(query_id: str, vct_values: list[str] | None, vct: str | None) -> None:
    # If the query named vct_values (parsed before the presentation was verified), the
    # disclosed vct MUST be one of them — the "right credential".
    if vct_values is None:
        return
    if vct not in vct_values:
        raise ClaimsInvalid(
            f"Credential Query {query_id!r}: vct {vct!r} is not one of the requested "
            f"vct_values")


def _type_values(query_id: str, query: Mapping[str, Any]) -> list[list[str]] | None:
    # DCQL meta.type_values constrains the acceptable W3C VC types (OpenID4VP 1.0 §B.1.1):
    # a non-empty array of alternatives, each a non-empty array of fully expanded type
    # IRIs. Absent means no constraint, as for vct_values. Anything else that is not that
    # shape (a non-object meta, an explicit null, an empty alternative) fails safe
    # (VpTokenMalformed) rather than silently widening to "any type".
    meta = _dcql_meta(query_id, query)
    if "type_values" not in meta:
        return None
    type_values = meta["type_values"]
    if (not isinstance(type_values, list) or not type_values
            or not all(isinstance(alt, list) and alt
                       and all(isinstance(t, str) and t for t in alt)
                       for alt in type_values)):
        raise VpTokenMalformed(
            f"Credential Query {query_id!r}: meta.type_values must be a non-empty array of "
            f"non-empty arrays of type IRIs")
    return type_values


def _require_pyld(query_id: str) -> None:
    # The match runs on JSON-LD expanded types; without a processor it cannot be decided,
    # so say so before verifying rather than accept an unchecked constraint. Kept apart
    # from the shape check in _type_values (#254): that one runs on every query up front,
    # and a well-formed type_values on a query the wallet did not answer needs no pyld.
    try:
        from pyld import jsonld  # noqa: F401
    except ImportError as exc:
        raise OpenID4VPError(
            f"Credential Query {query_id!r}: matching meta.type_values expands each "
            f"credential's types with JSON-LD, which needs pyld: "
            f"pip install 'openvc-core[data-integrity]'") from exc


def _check_type_values(
    query_id: str, type_values: list[list[str]] | None,
    credentials: Sequence[Any], extra_contexts: Mapping[str, dict] | None,
) -> None:
    # Every embedded credential must answer the query: its expanded types contain all the
    # IRIs of at least one alternative (any order, extra types allowed). Checking each one
    # stops an unrelated credential riding along in a VP that also carries the right one.
    if type_values is None:
        return
    from .proof.contexts import document_loader

    loader = document_loader(extra_contexts)
    for index, result in enumerate(credentials):
        expanded = _expanded_types(query_id, index, result, loader)
        if not any(all(t in expanded for t in alt) for alt in type_values):
            raise ClaimsInvalid(
                f"Credential Query {query_id!r}: embedded credential #{index} has none of "
                f"the requested type_values")


# A document base no real IRI can mean. A type no context defines resolves against it and
# is mapped back to the string as written (OpenID4VP 1.0 §B.1.1: it "remains a relative
# IRI"), while a context's own absolute @base still applies, as in JSON-LD (pyld ignores a
# context @base when the document base is None).
_RELATIVE_BASE = "https://openvc.invalid/relative/"


def _expanded_types(query_id: str, index: int, result: Any, loader: Any) -> frozenset[str]:
    """The fully expanded IRIs of a verified W3C credential's ``type``, as JSON-LD gives
    them after applying the credential's own ``@context`` (OpenID4VP 1.0 §B.1.1).

    Types are read from the credential's JSON, so only a format whose JSON is what its
    proof covers counts: a VC-JWT, a JCS Data Integrity credential, and an
    RDF-canonicalized one (``eddsa-rdfc-2022``, ``ecdsa-rdfc-2019``, ``ecdsa-sd-2023``),
    whose suite has already required that JSON to be the compacted form of the signed
    dataset under trusted contexts (context validation, GHSA-vrxg-57v4-85mc). An SD-JWT
    has no W3C ``type`` to match, and its holder could reshape one by withholding
    disclosures, so it yields none. Only ``@context`` and ``type`` are expanded: the credential is a
    top-level node, so nothing else in it changes how its types expand. Each call gets
    its own pyld context resolver, so no context processed here is cached for, or taken
    from, another call."""
    from pyld import jsonld

    from .proof.contexts import DocumentLoaderError, pyld_options
    from .verify import (
        FORMAT_DI_ECDSA_JCS,
        FORMAT_DI_ECDSA_RDFC,
        FORMAT_DI_ECDSA_SD,
        FORMAT_DI_EDDSA,
        FORMAT_DI_EDDSA_JCS,
        FORMAT_VC_JWT,
    )

    credential = getattr(result, "credential", None)
    if (getattr(result, "format", None) not in (
            FORMAT_VC_JWT, FORMAT_DI_EDDSA_JCS, FORMAT_DI_ECDSA_JCS, FORMAT_DI_EDDSA,
            FORMAT_DI_ECDSA_RDFC, FORMAT_DI_ECDSA_SD)
            or not isinstance(credential, Mapping)):
        return frozenset()
    document = {key: credential[key] for key in ("@context", "type") if key in credential}
    try:
        expanded = jsonld.expand(document, pyld_options(loader, base=_RELATIVE_BASE))
    except Exception as exc:
        # pyld wraps a loader refusal in its own JsonLdError: surface the actionable
        # "unbundled context" error if it caused this (as Data Integrity does). Anything
        # else is a credential whose types cannot be expanded, so it cannot match. The
        # message names the pyld error code only: its details hold the hostile document.
        cause: BaseException | None = exc
        for _ in range(8):
            if isinstance(cause, DocumentLoaderError):
                raise cause
            if cause is None:
                break
            cause = cause.__cause__ or cause.__context__
        code = getattr(exc, "code", None)
        raise ClaimsInvalid(
            f"Credential Query {query_id!r}: cannot expand the types of embedded "
            f"credential #{index} to match type_values "
            f"({code if isinstance(code, str) else type(exc).__name__})") from exc
    written = document.get("type")
    written = [written] if isinstance(written, str) else written
    types: set[str] = set()
    for node in expanded if isinstance(expanded, list) else ():
        values = node.get("@type") if isinstance(node, Mapping) else None
        for value in values if isinstance(values, list) else [values]:
            if not isinstance(value, str):
                continue
            if value.startswith(_RELATIVE_BASE):
                # a type no context defines: kept only if that is exactly what was written
                # (a dot-segment form like "./T" resolved into something else is dropped)
                value = value[len(_RELATIVE_BASE):]
                if not isinstance(written, list) or value not in written:
                    continue
            elif value.startswith("https://openvc.invalid/"):
                continue                     # "../T" climbed out of the sentinel base
            types.add(value)
    return frozenset(types)
