"""
openvc.proof.sd_jwt — SD-JWT VC proof suite (selective disclosure).

Implements the IETF SD-JWT VC family:
  * RFC 9901 (the SD-JWT mechanism; formerly draft-ietf-oauth-selective-disclosure-jwt)
  * draft-ietf-oauth-sd-jwt-vc-18 (the VC profile: ``vct``, ``aka_vcts``, ``cnf``,
    ``status`` …; a draft that builds on RFC 9901)

The same suite verifies a W3C VCDM credential secured as SD-JWT (VC-JOSE-COSE §3.2:
``vc+sd-jwt``, the draft-era ``vc+ld+json+sd-jwt``, or no ``typ``), accepted only as a
conforming VCDM payload (#275).

The third proof profile alongside VC-JWT (:mod:`openvc.proof.vc_jwt`) and Data
Integrity — and the format EUDI/ARF converges on. It reuses the same JOSE
machinery: the ``SigningKey`` backend (HSM-friendly, the private key never enters
the process) and the fixed ``{ES256, ES384, EdDSA, Ed25519}`` algorithm allow-list
checked before any crypto runs.

How SD-JWT works, briefly
-------------------------
Selectively-disclosable claims are removed from the issuer-signed JWT and each is
replaced by the **digest** of a *disclosure* — a salted ``[salt, name, value]``
(object) or ``[salt, value]`` (array element) blob. The digests live under ``_sd``
(objects) or as ``{"...": digest}`` (array elements). The combined presentation is

    <issuer-signed-jwt>~<disclosure 1>~...~<disclosure N>~<optional KB-JWT>

The holder chooses which disclosures to send; the verifier hashes each received
disclosure, matches it against the digests, and reconstructs only the disclosed
claims. A **Key Binding JWT** (``typ: kb+jwt``), signed by the holder key named in
the issuer's ``cnf``, binds a presentation to an audience + nonce and to the exact
set of disclosures (via ``sd_hash``), and dates it: its ``iat`` is required and must
fall within ``kb_max_age_s`` of the verifier's ``now`` (RFC 9901 §7.3 step 5.5).

Revocation: the suite itself does not check status. :func:`openvc.verify.verify_credential`
does (an SD-JWT VC's ``status`` claim carrying an IETF Token Status List reference, or a
W3C ``credentialStatus``), fail-closed by default; called directly, check it with
:func:`openvc.status.check_token_status` over the verified claims.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from .. import _json
from ..keys import KeyBackendError, verify_signature
from ._verify_common import (
    issuer_identifiers,
    DEFAULT_KB_MAX_AGE_S,
    check_iat_freshness,
    check_jwt_audience,
    check_jwt_temporal,
    check_numeric_dates,
    check_validity_window,
    leeway_seconds,
    non_negative_seconds,
    reject_unknown_crit,
    safe_repr,
    utc_epoch,
)
from .errors import (
    ClaimsInvalid,
    MalformedToken,
    ProofError,
    SignatureInvalid,
    UnsupportedAlgorithm,
)
from .vc_jwt import ALLOWED_ALGS, ALLOWED_ALGS_PQ, SigningKey, VcJwtProofSuite

DEFAULT_LEEWAY_S = 60
_HASHES = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
_DEFAULT_HASH = "sha-256"
_ISSUER_TYP = "dc+sd-jwt"                       # an IETF SD-JWT VC (draft-19 §2.2.1)
_KB_TYP = "kb+jwt"
# W3C VC-JOSE-COSE §6.1.3 registers `vc+sd-jwt` for a VCDM payload, and verify() accepts
# it only for one: a conforming payload, see _vcdm_nonconformity (#264, #275). The IETF
# drafts used it before draft-06 renamed it, but draft-19 dropped the transitional
# acceptance of it.
_W3C_TYP = "vc+sd-jwt"
# The name the Working Drafts of 2023 and the First Candidate Recommendation (25 April 2024)
# of VC-JOSE-COSE gave that media type (`application/vc+ld+json+sd-jwt`) before the rename.
# The Recommendation's Example 21 still carries it, and issuers built on those drafts emit it
# (#289). Exact match, same rule.
_W3C_DRAFT_TYP = "vc+ld+json+sd-jwt"
_W3C_TYPS = frozenset({_W3C_TYP, _W3C_DRAFT_TYP})
# The issuer JWT `typ` values verify() accepts. An absent `typ` is accepted too, for a
# conforming VCDM payload only (VC-JOSE-COSE §3.2.1 makes it a SHOULD, and the
# Recommendation's Examples 4 and 5 omit it, #288); a present one must be in this closed set.
_ACCEPTED_ISSUER_TYP = frozenset({_ISSUER_TYP}) | _W3C_TYPS
_VCDM_CONTEXTS = frozenset({
    "https://www.w3.org/ns/credentials/v2",            # VCDM 2.0
    "https://www.w3.org/2018/credentials/v1",          # VCDM 1.1
})
_SALT_BYTES = 16                               # 128-bit salt (spec minimum)
# Nesting bound for _unpack, parity with the sibling codecs (cbor.py=64, _jcs.py=100).
# A hostile presentation can nest claims deeply, or chain disclosures (each disclosing an
# object that carries the next _sd digest) so _unpack recurses far past what json.loads'
# own limit bounds. Fail closed with a typed error before Python raises RecursionError.
_MAX_DEPTH = 100
# Claims that must never sit in a disclosure. A holder may withhold any disclosure, and a
# withheld one is indistinguishable from a decoy (RFC 9901 §9.7), so a disclosable `exp` or
# `status` makes an expired or revoked credential verify. issue() refuses them; verify()
# rejects a presentation that discloses one, or a sub-claim of one. Withholding stays
# undetectable, so the issuer-side refusal is the real fix.
# draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: these, "including any of their sub-claims", MUST
# NOT be selectively disclosed (only `sub` and `iat` MAY be).
_SD_JWT_VC_NON_DISCLOSABLE = frozenset({
    "iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"})
# openvc policy: the pipeline enforces a W3C `credentialStatus` on SD-JWT too, and
# `@context` is what makes _declares_vcdm enforce the VCDM validity window — withheld, it
# would switch that window off (VC-JOSE-COSE §3.2.1: needed for validation, SHOULD NOT be
# disclosable).
_OPENVC_NON_DISCLOSABLE = frozenset({"credentialStatus", "@context"})
# On a W3C VCDM payload only: the validity window the suite enforces (VCDM 1.1 names too).
# On an IETF SD-JWT VC these names mean nothing and stay disclosable.
_VCDM_VALIDITY_CLAIMS = frozenset({"validFrom", "validUntil", "issuanceDate", "expirationDate"})


class SdJwtError(ProofError):
    """Malformed SD-JWT structure, disclosure, or key-binding."""


# --------------------------------------------------------------------------- #
# base64url + disclosure primitives
# --------------------------------------------------------------------------- #

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ascii_bytes(value: str) -> bytes:
    # Compact SD-JWT is base64url + '~'. Non-ASCII in a disclosure (or anywhere in
    # the presented string) must be a typed error: encode("ascii") raising
    # UnicodeEncodeError would escape OpenvcError and abort verify_many.
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SdJwtError("SD-JWT presentation is not ASCII") from exc


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def make_object_disclosure(salt: str, name: str, value: Any) -> str:
    """Encode an object-property disclosure ``[salt, name, value]``."""
    return _b64url_encode(_json_bytes([salt, name, value]))


def make_array_disclosure(salt: str, value: Any) -> str:
    """Encode an array-element disclosure ``[salt, value]``."""
    return _b64url_encode(_json_bytes([salt, value]))


def disclosure_digest(disclosure: str, *, hash_name: str = _DEFAULT_HASH) -> str:
    """The base64url digest of a disclosure string — hashed exactly as received
    (never re-serialized), which is why the verifier needs no canonicalization."""
    try:
        hasher = _HASHES[hash_name]
    except KeyError as exc:
        raise SdJwtError(f"unsupported _sd_alg {hash_name!r}") from exc
    return _b64url_encode(hasher(disclosure.encode("ascii")).digest())


# --------------------------------------------------------------------------- #
# recursive unpacking (the security-critical core)
# --------------------------------------------------------------------------- #

def _sd_digests(sd: Any) -> list[str]:
    if sd is None:
        return []
    if not isinstance(sd, list) or not all(isinstance(d, str) for d in sd):
        raise SdJwtError("_sd must be an array of digest strings")
    return sd


def _unpack(node: Any, disclosures: dict[str, list], used: set[str], seen: set[str],
            depth: int = 0, top: str | None = None,
            placed: list[tuple[str | None, bool]] | None = None) -> Any:
    """Rebuild *node*, replacing ``_sd`` digests and ``{"...": digest}`` array
    elements with the disclosed values. Rejects duplicate digests, digests reused
    by two disclosures, and disclosures that would overwrite an existing claim.

    ``depth`` bounds recursion (claims nesting *and* chained disclosures) so hostile
    input fails closed with a typed :class:`SdJwtError` before Python's RecursionError.

    *placed*, when given, records where every inserted disclosure landed, as
    ``(top-level claim, nested)``: ``("exp", False)`` for a disclosed top-level ``exp``,
    ``("status", True)`` for anything disclosed beneath ``status`` (array elements
    included). *top* is the top-level claim the node lies under (None at the root).
    That is generic RFC 9901 provenance: which names may be disclosed is the profile's
    rule, applied by the caller."""
    if depth > _MAX_DEPTH:
        raise SdJwtError(f"claim/disclosure nesting exceeds the maximum depth of {_MAX_DEPTH}")
    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, value in node.items():
            if key == "_sd":
                continue                       # processed below
            if key == "...":
                raise SdJwtError("'...' is only valid as an array element")
            result[key] = _unpack(value, disclosures, used, seen, depth + 1,
                                  key if top is None else top, placed)
        for digest in _sd_digests(node.get("_sd")):
            if digest in seen:
                raise SdJwtError("duplicate digest in payload")
            seen.add(digest)
            disclosure = disclosures.get(digest)
            if disclosure is None:
                continue                       # decoy or simply not disclosed
            if len(disclosure) != 3:
                raise SdJwtError("object disclosure must be [salt, name, value]")
            name = disclosure[1]
            if not isinstance(name, str):
                raise SdJwtError("disclosure claim name must be a string")
            if name in ("_sd", "..."):
                raise SdJwtError(f"disclosure claim name {name!r} is reserved")
            if name in result:
                raise SdJwtError(f"disclosure would overwrite claim {name!r}")
            used.add(digest)
            if placed is not None:
                placed.append((name, False) if top is None else (top, True))
            result[name] = _unpack(disclosure[2], disclosures, used, seen, depth + 1,
                                   name if top is None else top, placed)
        return result
    if isinstance(node, list):
        out: list[Any] = []
        for element in node:
            if isinstance(element, dict) and set(element) == {"..."}:
                digest = element["..."]
                if not isinstance(digest, str):
                    raise SdJwtError("array digest must be a string")
                if digest in seen:
                    raise SdJwtError("duplicate digest in payload")
                seen.add(digest)
                disclosure = disclosures.get(digest)
                if disclosure is None:
                    continue                   # undisclosed array element
                if len(disclosure) != 2:
                    raise SdJwtError("array disclosure must be [salt, value]")
                used.add(digest)
                if placed is not None:          # the root is an object, so `top` is set
                    placed.append((top, True))
                out.append(_unpack(disclosure[1], disclosures, used, seen, depth + 1,
                                   top, placed))
            else:
                out.append(_unpack(element, disclosures, used, seen, depth + 1,
                                   top, placed))
        return out
    return node


def _disclosure_refusal(name: Any, *, vcdm: bool) -> str | None:
    """Why the top-level claim *name* may not be selectively disclosed (nor any
    sub-claim of it), or None when it may. *vcdm*: the payload is a W3C VCDM
    credential (:func:`_declares_vcdm`), whose validity window the suite enforces."""
    if not isinstance(name, str):
        return None
    if name in _SD_JWT_VC_NON_DISCLOSABLE:
        return "draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3"
    if name in _OPENVC_NON_DISCLOSABLE:
        return "openvc enforces it on SD-JWT"
    if vcdm and name in _VCDM_VALIDITY_CLAIMS:
        return "the W3C VCDM validity window openvc enforces"
    return None


# --------------------------------------------------------------------------- #
# result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedSdJwt:
    claims: dict[str, Any]         # the fully-disclosed claim set (``_sd`` resolved)
    issuer: str                    # ``iss``, or the VCDM ``issuer`` when there is none (#290)
    vct: str | None                # verifiable credential type
    key_bound: bool                # a valid KB-JWT was present and verified
    confirmation: dict[str, Any] | None   # the ``cnf`` claim, if any
    # check_temporal=False only: the issuer JWT's ``exp`` has passed — or, for a W3C
    # VCDM payload, its ``validUntil`` — i.e. the expiry check that was skipped would
    # have failed. An IETF SD-JWT VC's claim merely named ``validUntil`` never sets it.
    expired: bool = False
    # the payload is a W3C VCDM credential (a VCDM ``@context``, see ``_declares_vcdm``),
    # whose validity window and issuer / id / subject consistency the suite enforced
    vcdm: bool = False
    # the verified issuer JWT ``typ``: ``dc+sd-jwt`` (an IETF SD-JWT VC, with a ``vct``),
    # ``vc+sd-jwt`` or the draft-era ``vc+ld+json+sd-jwt`` (a W3C VCDM payload,
    # VC-JOSE-COSE), or None when the issuer JWT carried no ``typ`` (a SHOULD there; accepted
    # for a VCDM payload only) or the object was not built by verify().
    typ: str | None = None


def _check_aka_vcts(payload: Mapping[str, Any]) -> None:
    """draft-18 §2.2.2.2: ``aka_vcts``, when present, is a non-empty array of
    additional types and MUST NOT contain the credential's ``vct``.

    Absent is fine — the claim is optional. ``expected_vct`` is deliberately
    *not* widened to match these aliases: that pin is exact, and a union here
    would be a scope escalation. Callers that want alias matching read
    ``claims["aka_vcts"]`` themselves.
    """
    aka = payload.get("aka_vcts")
    if aka is None:
        return
    if (not isinstance(aka, (list, tuple)) or not aka
            or not all(isinstance(item, str) and item for item in aka)):
        raise ClaimsInvalid(
            "aka_vcts must be a non-empty array of non-empty strings when present")
    vct = payload.get("vct")
    if isinstance(vct, str) and vct in aka:
        raise ClaimsInvalid("aka_vcts must not contain the credential's vct")


def _declares_vcdm(claims: Mapping[str, Any]) -> bool:
    """Whether a processed SD-JWT payload is a W3C VCDM credential (VC-JOSE-COSE §3.2.1),
    whose ``validFrom`` / ``validUntil`` (VCDM 1.1: ``issuanceDate`` / ``expirationDate``)
    are then enforced as on the VC-JWT lane: its ``@context`` names a VCDM base context
    (as a string or anywhere in an array). verify() refuses a presented ``@context``
    disclosure, so the verdict never reads a holder-supplied one. It cannot see one a
    third-party issuer made disclosable and the holder withheld (RFC 9901 §9.7): that
    payload reads as not VCDM.

    The ``typ`` is not a signal. ``vc+sd-jwt`` without a VCDM ``@context`` used to count,
    which let a ``vct``-less (or ``vct``-withheld) token skip the REQUIRED ``vct`` of an
    IETF SD-JWT VC; verify() now refuses that ``typ``, the draft-era ``vc+ld+json+sd-jwt``
    and an absent ``typ`` unless this returns True (#264, #288, #289).

    An IETF SD-JWT VC that merely has a claim *named* ``validUntil`` is not VCDM: the name
    means nothing in its vocabulary, so it is not read as a validity bound.

    This is the lax test, on purpose: it decides which payloads get the validity window and
    the issuer / subject consistency checks, so a base URL in second place still turns them
    on. Being *read as* a W3C credential takes more (:func:`_vcdm_nonconformity`, #275)."""
    context = claims.get("@context")
    entries = context if isinstance(context, list) else [context]
    return any(isinstance(entry, str) and entry in _VCDM_CONTEXTS for entry in entries)


def _declares_credential(claims: Mapping[str, Any]) -> bool:
    """Whether a processed VCDM payload says it is a *credential*: its ``type`` (a string or
    an array) includes ``VerifiableCredential`` (VCDM 2.0 §4.5) and not
    ``VerifiablePresentation`` (§4.13).

    Read for every issuer JWT that is not a ``dc+sd-jwt`` (#275). With no ``typ`` it is what
    tells a credential from a presentation: a VCDM 2.0 presentation secured with SD-JWT
    carries the same ``@context`` as a credential, with no ``vp`` claim to ban, so without it
    a holder-signed presentation with no ``typ`` would verify as a credential issued by the
    holder (#293, found reviewing #292, before any release). With a W3C ``typ`` it keeps a
    payload that is not a credential from passing under a ``typ`` that says it is. It is a
    positive test, so a ``type`` that is absent or withheld (the Recommendation's own
    Example 4 makes it selectively disclosable) is refused, not waved through, and only the
    compact term counts: a full IRI or a prefixed name is refused too."""
    declared = claims.get("type")
    names = {entry for entry in (declared if isinstance(declared, list) else [declared])
             if isinstance(entry, str)}
    return "VerifiableCredential" in names and "VerifiablePresentation" not in names


def _vcdm_issuer(body: Mapping[str, Any]) -> str | None:
    """The issuer a W3C credential names in its VCDM ``issuer`` property, or None when it
    names no one usable (#290). A string is itself; an object is identified by its ``id`` /
    ``@id`` members that are present (``id`` aliases ``@id`` in JSON-LD), which must all be
    the same non-empty string: an object with neither, or whose two members disagree, names
    no one and is refused rather than guessed at, as the reconciliation reads it.

    Used only for an issuer JWT whose body has NO ``iss`` and whose ``typ`` is a W3C state.
    VC-JOSE-COSE §4.1.2 says that ``iss``, if present, MUST match the ``issuer``; §4.2 says
    that when ``iss`` is absent and the issuer is a URL, the ``kid`` MUST be an absolute URL
    to a verification method in the issuer's controlled identifier document or DID document.
    openvc takes the identifier from ``issuer`` and resolves it with the same paths as
    ``iss``. Always read from the issuer-JWT *body*: a disclosure is never consulted, so
    a holder cannot supply the identifier that selects the key, and the value is exactly as
    unauthenticated as ``iss`` is until the signature verifies."""
    identifiers = issuer_identifiers(body.get("issuer"))
    if not identifiers or not all(isinstance(i, str) and i for i in identifiers):
        return None
    return identifiers[0] if len(set(identifiers)) == 1 else None


def _may_use_vcdm_issuer(body: Mapping[str, Any], header: Mapping[str, Any]) -> bool:
    """Whether the VCDM ``issuer`` may stand in for ``iss`` (#290): the body has no ``iss``
    member at all and the header ``typ`` is a W3C state, absent, ``vc+sd-jwt`` or the draft-era
    ``vc+ld+json+sd-jwt``. A present ``iss`` that is null, empty or not a string is NOT
    replaced by ``issuer``: the caller refuses it. A ``typ`` that is present and anything
    else, ``null`` and a non-string included, is not a W3C state either: ``dc+sd-jwt`` keeps
    requiring ``iss``, and an unaccepted ``typ`` is refused by verify() before it matters.
    Both headers and bodies are untrusted here, so *typ* may be any JSON value."""
    if "iss" in body:
        return False
    if "typ" not in header:
        return True
    typ = header["typ"]
    return isinstance(typ, str) and typ in _W3C_TYPS


def _issuer_from_body(body: Mapping[str, Any], header: Mapping[str, Any]) -> Any:
    """The identifier that selects the issuer key and names the issuer: the ``iss`` claim,
    or, where :func:`_may_use_vcdm_issuer` allows it, the VCDM ``issuer`` of the body
    (:func:`_vcdm_issuer`). Whatever ``iss`` holds when it is present is returned as it is,
    for the caller to refuse."""
    if _may_use_vcdm_issuer(body, header):
        return _vcdm_issuer(body)
    return body.get("iss")


_NO_USABLE_ISSUER = " (and no usable VCDM `issuer` for a W3C credential)"


def _starts_with_base_context(claims: Mapping[str, Any]) -> bool:
    """Whether the payload's ``@context`` starts with a VCDM base context (VCDM 2.0 §4.3:
    "an ordered set where the first item" is the base URL; VCDM 1.1 §4.1 says the same of
    its own). :func:`_declares_vcdm` accepts that URL *anywhere*, which is what keeps the
    validity window and the consistency checks on; this is the stricter test a payload must
    pass to be *read as* a W3C credential (#275). A string ``@context`` is its own first
    item. An embedded context object, or an empty array, in first place does not count."""
    context = claims.get("@context")
    first = context[0] if isinstance(context, list) and context else context
    return isinstance(first, str) and first in _VCDM_CONTEXTS


def _vcdm_nonconformity(claims: Mapping[str, Any]) -> str | None:
    """Which requirement a payload that names a VCDM base context somewhere still fails to
    meet to be read as a W3C credential, or None when it meets them (#275). Judged on the
    PROCESSED payload (what :meth:`SdJwtVcProofSuite.verify` returns as ``claims``):
    ``@context`` is never disclosable (a presented disclosure of it is refused), and a
    withheld ``type`` makes the payload fail the second requirement instead of passing it.
    The message names the requirement, so a caller can tell a misplaced context from a
    missing ``type``.

    Not everything here is issuer-signed plaintext: an issuer that made an *array element*
    of ``@context`` or ``type`` selectively disclosable lets the verdict depend on what the
    holder presents, because a withheld element is gone and the positions shift. That needs
    the signer's grant, ``vcdm`` stays True so the window still runs, and it is pinned in
    ``tests/test_sd_jwt_vcdm_conformance.py`` as a documented limit.

    Only two things are tested. Non-string ``type`` entries are ignored, a full-IRI
    ``VerifiablePresentation`` is not recognised, ``[V1, V2]`` passes, later ``@context``
    items are not looked at, and ``issuer`` / ``credentialSubject`` are not required."""
    if not _starts_with_base_context(claims):
        return ("needs a VCDM base context as the first `@context` entry "
                "(VCDM 2.0 §4.3), not just somewhere in it")
    if not _declares_credential(claims):
        return ("needs a `type` that includes VerifiableCredential and not "
                "VerifiablePresentation (VCDM 2.0 §4.5, §4.13)")
    return None


# --------------------------------------------------------------------------- #
# proof suite
# --------------------------------------------------------------------------- #

class SdJwtVcProofSuite:
    """SD-JWT VC issuance, holder presentation, and verification."""

    def __init__(
        self, *, leeway_s: int = DEFAULT_LEEWAY_S, hash_name: str = _DEFAULT_HASH,
        allow_pq: bool = False,
    ) -> None:
        # Added to both edges of every window here, so NaN would switch them off.
        self._leeway = leeway_seconds(leeway_s, error=SdJwtError)
        if hash_name not in _HASHES:
            raise SdJwtError(f"unsupported hash {hash_name!r}")
        self._hash_name = hash_name
        # allow_pq merges the EXPERIMENTAL ML-DSA algs into this suite's allow-list; the
        # default suite rejects ML-DSA at the allow-list, before any crypto (ADR-0004).
        self._algs = ALLOWED_ALGS | ALLOWED_ALGS_PQ if allow_pq else ALLOWED_ALGS

    # -- untrusted inspection --------------------------------------------- #

    def peek_issuer(self, sd_jwt: str) -> tuple[str, str | None]:
        """Return (iss, kid) from the issuer-signed JWT WITHOUT verifying.
        UNTRUSTED — use only to select which key to resolve.

        For a W3C credential (``typ`` absent, ``vc+sd-jwt`` or ``vc+ld+json+sd-jwt``) whose
        body has no ``iss`` at all, the first item is the VCDM ``issuer`` (a string, or an
        object's ``id``): VC-JOSE-COSE §4.1.2 makes ``iss`` optional there (#290). Stricter
        than the VC-JWT lane's peek, which reads ``vc.issuer`` for any falsy ``iss``: only
        when ``iss`` is ABSENT, and an object's ``id`` / ``@id`` must all agree. A
        ``dc+sd-jwt`` still needs ``iss``."""
        header, payload, _, _ = self._decode_jws(sd_jwt.split("~", 1)[0])
        iss = _issuer_from_body(payload, header)
        if not iss or not isinstance(iss, str):
            raise MalformedToken(
                "no iss in the issuer-signed JWT"
                + (_NO_USABLE_ISSUER if _may_use_vcdm_issuer(payload, header) else ""))
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise MalformedToken("kid must be a string")
        return iss, kid

    # -- issuance --------------------------------------------------------- #

    def issue(
        self,
        claims: dict[str, Any],
        *,
        signing_key: SigningKey,
        disclosable: Iterable[str] = (),
        holder_jwk: dict[str, Any] | None = None,
        vct: str | None = None,
        expires_in_s: int | None = None,
        decoys: int = 0,
        x5c: Iterable[str] | None = None,
    ) -> str:
        """Issue an SD-JWT VC: ``<issuer-jwt>~<disclosure>~...~``.

        ``disclosable`` names the top-level claims to make selectively
        disclosable (each leaves the JWT for a disclosure + an ``_sd`` digest).
        It refuses (``SdJwtError``, nothing signed) the claims a verifier needs to judge
        validity, since a holder could withhold them undetected: ``iss``, ``nbf``,
        ``exp``, ``cnf``, ``vct``, ``vct#integrity``, ``aka_vcts`` and ``status``
        (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3), ``credentialStatus`` and ``@context``,
        and — when ``@context`` makes the payload a W3C VCDM credential — ``validFrom``,
        ``validUntil``, ``issuanceDate`` and ``expirationDate``. ``holder_jwk`` binds
        the credential to a holder key (``cnf``) for later key binding.
        ``decoys`` adds that many decoy digests (privacy). The raw
        signature is produced by ``signing_key`` — HSM/Vault friendly.

        ``x5c`` places an X.509 certificate chain (base64 DER, leaf first) in the
        issuer JWT header, so a verifier that anchors trust in a trusted list can
        validate it in one call: ``verify_credential(sd_jwt, x5c_trust_anchors=[…])``
        chains the leaf to those anchors and binds it to ``iss`` (see :mod:`openvc.x5c`).
        The leaf certificate's key MUST be the *signing_key*'s public key, and ``iss``
        must appear in the leaf's Subject Alternative Name, or verification fails closed.
        """
        if signing_key.alg not in self._algs:
            raise UnsupportedAlgorithm(f"key alg {signing_key.alg!r} not permitted")

        now = int(time.time())
        payload: dict[str, Any] = dict(claims)
        payload.setdefault("iat", now)
        if vct is not None:
            payload["vct"] = vct
        if not payload.get("iss"):
            raise SdJwtError("an SD-JWT VC needs an 'iss' claim")
        if not (isinstance(payload.get("vct"), str) and payload["vct"]):
            # what verify() requires of a dc+sd-jwt: anything else would not verify
            raise SdJwtError("an SD-JWT VC needs a 'vct' claim (a non-empty string)")
        _check_aka_vcts(payload)
        if expires_in_s is not None:
            payload["exp"] = now + expires_in_s
        if holder_jwk is not None:
            payload["cnf"] = {"jwk": holder_jwk}

        names = list(disclosable)
        # Judge VCDM-ness on the payload as the verifier will parse it: a tuple
        # `@context` is not a list here, but it is a JSON array once signed.
        vcdm = _declares_vcdm(json.loads(_json_bytes(payload)))
        for name in names:                     # refuse before any disclosure is built
            reason = _disclosure_refusal(name, vcdm=vcdm)
            if reason is not None:
                raise SdJwtError(
                    f"claim {name!r} must not be selectively disclosable ({reason}): a "
                    "holder could withhold it, and a verifier cannot tell a withheld "
                    "disclosure from an absent claim")

        disclosures: list[str] = []
        digests: list[str] = []
        for name in names:
            if name not in payload:
                raise SdJwtError(f"disclosable claim {name!r} is not in the claims")
            disclosure = make_object_disclosure(
                _b64url_encode(secrets.token_bytes(_SALT_BYTES)), name, payload.pop(name))
            disclosures.append(disclosure)
            digests.append(disclosure_digest(disclosure, hash_name=self._hash_name))
        digest_size = _HASHES[self._hash_name]().digest_size
        for _ in range(decoys):
            digests.append(_b64url_encode(secrets.token_bytes(digest_size)))
        if digests:
            payload["_sd"] = sorted(digests)           # sorted: order leaks nothing
            payload["_sd_alg"] = self._hash_name

        header: dict[str, Any] = {
            "typ": _ISSUER_TYP, "alg": signing_key.alg, "kid": signing_key.kid}
        if x5c is not None:
            chain = list(x5c)
            if not chain or not all(isinstance(c, str) and c for c in chain):
                raise SdJwtError("x5c must be a non-empty list of base64 certificate strings")
            header["x5c"] = chain
        issuer_jwt = self._sign_compact(header, payload, signing_key)
        return issuer_jwt + "~" + "".join(d + "~" for d in disclosures)

    # -- holder presentation ---------------------------------------------- #

    def create_presentation(
        self,
        sd_jwt: str,
        *,
        holder_key: SigningKey,
        audience: str,
        nonce: str,
    ) -> str:
        """Holder side: attach a Key Binding JWT over the (all-disclosure)
        presentation, bound to *audience* and *nonce*. Returns the full
        ``<issuer-jwt>~<disclosures>~<KB-JWT>``."""
        if holder_key.alg not in self._algs:
            raise UnsupportedAlgorithm(f"holder key alg {holder_key.alg!r} not permitted")
        issuer_jwt, disclosures, _ = self._split(sd_jwt)
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        sd_hash = _b64url_encode(
            _HASHES[self._hash_name](_ascii_bytes(presented)).digest())
        header = {"typ": _KB_TYP, "alg": holder_key.alg}
        payload = {"iat": int(time.time()), "aud": audience, "nonce": nonce, "sd_hash": sd_hash}
        return presented + self._sign_compact(header, payload, holder_key)

    # -- verification ------------------------------------------------------ #

    def verify(
        self,
        presentation: str,
        *,
        public_key_jwk: dict[str, Any],
        audience: str | None = None,
        nonce: str | None = None,
        require_key_binding: bool = False,
        expected_vct: str | None = None,
        check_temporal: bool = True,
        kb_max_age_s: int = DEFAULT_KB_MAX_AGE_S,
        now: datetime | None = None,
    ) -> VerifiedSdJwt:
        """Verify an SD-JWT (VC) presentation end to end.

        Verifies the issuer signature + temporal claims, validates and unpacks the
        disclosures, and — if a KB-JWT is present (or required) — verifies it
        against the holder key in ``cnf`` and checks ``aud`` / ``nonce`` /
        ``sd_hash``.

        *audience* and *nonce* bind a KB-JWT **together** (RFC 9901 §7.3 step 5.6):
        pass both, as non-empty strings. A present KB-JWT verified with only one of
        them, or with an empty one, raises ``ClaimsInvalid`` rather than report a
        half-checked binding. With neither, ``key_bound=True`` proves possession of the
        ``cnf`` key over these disclosures for *some* verifier, not a binding to you.
        Rejecting a half-bound KB-JWT does not make it *required*: a presentation with
        the KB-JWT stripped still verifies with ``key_bound=False``, so set
        *require_key_binding* (or check ``key_bound``) when you need the binding.

        When *require_key_binding* is True the KB-JWT is verified **before**
        ``exp``/``nbf``: an expired (or not-yet-valid) issuer JWT still has its
        holder binding checked, so a temporal failure means the presentation was
        bound and a key-binding failure means it was not. The hosted path
        (*require_key_binding* False) is unchanged — temporal still runs before
        any optional KB-JWT.

        Any KB-JWT that is present is held to RFC 9901 §7.3 step 5.5: its ``iat`` is
        required, must be a finite number, must not be older than *kb_max_age_s* (plus
        the suite leeway) and must not be in the future beyond the leeway. *now* pins
        the instant that window is evaluated at (a naive datetime is UTC). To re-check
        an archived presentation, pin it to the **receipt time your system recorded** —
        never to a value read from the presentation itself: its own ``iat`` would make
        every KB-JWT fresh and switch the window off. The issuer JWT's ``exp``/``nbf``/``iat``
        still use the current time, as on every JOSE suite.

        The issuer JWT ``typ`` is ``dc+sd-jwt`` (an IETF SD-JWT VC) or ``vc+sd-jwt``
        (VC-JOSE-COSE §6.1.3). The draft-era ``vc+ld+json+sd-jwt`` of the Recommendation's
        Example 21 and an absent ``typ`` (a SHOULD there; its Examples 4 and 5 omit it) are
        accepted like ``vc+sd-jwt``. All of these but ``dc+sd-jwt`` are accepted only for
        a payload that conforms to the VCDM (#275): a VCDM base ``@context`` somewhere in it
        (otherwise ``SdJwtError``), as the FIRST ``@context`` entry (VCDM 2.0 §4.3), and a
        ``type`` that includes ``VerifiableCredential`` and not ``VerifiablePresentation``
        (§4.5, §4.13), each with its own ``SdJwtError`` message; a withheld ``type`` fails the
        second. Nothing more is tested: ``issuer`` and ``credentialSubject`` are not required.
        A ``typ`` that is present and anything else, ``null`` included, raises ``SdJwtError``
        too, and so does an absent one on a payload with a ``vc`` or ``vp`` claim (§3.1.3).
        When the payload names a VCDM ``@context`` anywhere (whatever the ``typ``, a
        ``dc+sd-jwt`` included), it is a W3C VCDM credential for what follows, and its
        ``validFrom`` / ``validUntil`` are enforced too, like the VC-JWT suite does (current
        time, same leeway; ``check_temporal=False`` waives only the expiry). Its ``iss`` /
        ``jti`` / ``sub`` must not conflict with ``issuer`` / ``id`` /
        ``credentialSubject.id`` either, as on the VC-JWT suite (``ClaimsInvalid``). An IETF
        SD-JWT VC's claims are never read as a VCDM validity window or reconciled with them.

        The issuer JWT's ``exp``/``nbf``/``iat``, and any disclosed ``iat``, must each be
        a finite JSON number when present (``null`` included). An ``iat`` more than the
        leeway in the future is rejected. *check_temporal* waives only an expired ``exp``.

        The issuer JWT's own ``aud``, when it has one, is held to RFC 7519 §4.1.3 (ADR-0008
        D4): it must be a string or an array of strings, and the *audience* you pass must be
        one of them, else ``ClaimsInvalid``. With no *audience* a credential that names an
        audience is refused, since you cannot be one of them. An issuer JWT with no ``aud``
        verifies as before, with or without an *audience*. The check reads the processed
        payload, runs after the KB-JWT when binding is required, is not an expiry (so
        *check_temporal* does not waive it, and its message does not describe an expiry), and
        cannot see an ``aud`` disclosure the holder withholds. The KB-JWT's ``aud`` is a
        separate check: it binds the holder's presentation, not the issuer's restriction.

        A presented disclosure of a claim :meth:`issue` refuses to make disclosable — or of
        any sub-claim of one, array elements included — raises ``SdJwtError``: the issuer
        made it withholdable. That catches the non-conformant issuer only when the holder
        *presents* the disclosure; a withheld one is indistinguishable from a decoy (RFC
        9901 §9.7), so a third-party credential whose ``exp`` or ``status`` was disclosable
        still verifies when the holder omits it. Besides the issuer identifier (``iss``, or for
        a W3C credential with no ``iss`` its VCDM ``issuer``, #290), without which nothing
        verifies, the detectable case is ``vct``: it is REQUIRED, so a ``dc+sd-jwt`` whose
        processed payload has none raises ``ClaimsInvalid``, even one that also carries a
        VCDM ``@context``. With *require_key_binding*, a disclosed ``cnf`` fails earlier,
        as the key-binding ``ClaimsInvalid`` (no ``cnf.jwk`` in the issuer JWT).
        """
        non_negative_seconds(kb_max_age_s, name="kb_max_age_s", error=SdJwtError)
        # A naive `now` is UTC. Unpinned, the KB-JWT window reads the clock unrounded, as
        # check_jwt_temporal does: truncating it would accept a fractional KB-JWT `exp` up
        # to a second late. A pin is read to the second, as every openvc clock check is.
        current: float = time.time() if now is None else utc_epoch(now, error=SdJwtError)
        issuer_jwt, disclosures, kb_jwt = self._split(presentation)
        header, claims, signing_input, signature = self._decode_jws(issuer_jwt)

        # allow-list BEFORE crypto. A JSON array/object `alg` / `typ` is unhashable:
        # type-check it first, or `in frozenset` raises a bare TypeError
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._algs:
            raise UnsupportedAlgorithm(f"algorithm {safe_repr(alg)} is not permitted")
        # An ABSENT `typ` is let through (None) and judged on the payload below; one that is
        # present must be an accepted string. `null`, a number, an array and an object are
        # present and wrong, and a JSON array/object is unhashable, so type-check first.
        typ = header.get("typ")
        if "typ" in header and (not isinstance(typ, str) or typ not in _ACCEPTED_ISSUER_TYP):
            raise SdJwtError(f"unexpected issuer JWT typ {safe_repr(typ)}")
        reject_unknown_crit(header)
        self._verify_signature(alg, public_key_jwk, signing_input, signature,
                               what="issuer JWT")

        def _iss_and_hash() -> tuple[str, str]:
            # `header["typ"]` was accepted above: absent, a W3C name or dc+sd-jwt (#290)
            iss_claim = _issuer_from_body(claims, header)
            if not isinstance(iss_claim, str) or not iss_claim:
                raise ClaimsInvalid(
                    "iss claim is missing or not a string"
                    + (_NO_USABLE_ISSUER if _may_use_vcdm_issuer(claims, header) else ""))
            alg_name = claims.get("_sd_alg", _DEFAULT_HASH)
            if not isinstance(alg_name, str) or alg_name not in _HASHES:
                raise SdJwtError(f"unsupported _sd_alg {safe_repr(alg_name)}")
            return iss_claim, alg_name

        # Presentation path: prove holder binding even when the issuer JWT is
        # expired / not-yet-valid, then surface the temporal verdict. A
        # "token has expired" after this call means the KB-JWT verified.
        # Hosted / no-KB path: temporal first, same order as before.
        if require_key_binding:
            iss, hash_name = _iss_and_hash()
            key_bound = self._verify_key_binding(
                kb_jwt, issuer_jwt, disclosures, claims.get("cnf"),
                hash_name=hash_name, audience=audience, nonce=nonce,
                required=True, current=current, max_age_s=kb_max_age_s)
            expired = self._check_temporal(claims, check_temporal=check_temporal)
        else:
            expired = self._check_temporal(claims, check_temporal=check_temporal)
            iss, hash_name = _iss_and_hash()
            key_bound = False

        by_digest = self._index_disclosures(disclosures, hash_name)
        used: set[str] = set()
        placed: list[tuple[str | None, bool]] = []
        unpacked = _unpack(claims, by_digest, used, set(), placed=placed)
        unreferenced = set(by_digest) - used
        if unreferenced:
            raise SdJwtError(
                f"{len(unreferenced)} disclosure(s) not referenced by any digest")
        unpacked.pop("_sd_alg", None)

        # The profile rule on what _unpack placed: a presented disclosure of `exp`,
        # `status`, … (or of any sub-claim, array elements included) means the issuer made
        # it withholdable — fail visibly now rather than open when a holder withholds it.
        # `@context` is refused too, so the VCDM verdict below rests on issuer-signed
        # plaintext. This cannot see a disclosure that was withheld.
        vcdm = _declares_vcdm(unpacked)
        for name, nested in placed:
            reason = _disclosure_refusal(name, vcdm=vcdm)
            if reason is not None:
                what = "a sub-claim of" if nested else "claim"
                raise SdJwtError(
                    f"{what} {name!r} is selectively disclosed ({reason}): the issuer "
                    "made it withholdable, so its absence would go undetected")
        if typ != _ISSUER_TYP:
            # VC-JOSE-COSE §6.1.3 registers `vc+sd-jwt` for a VCDM payload, and draft-19
            # dropped the transitional acceptance of it for an IETF SD-JWT VC. Read as VCDM
            # by its typ alone, a `vct`-less or `vct`-withheld token skipped the REQUIRED
            # `vct` below (#264). A presented `@context` disclosure was refused above; a
            # withheld one leaves the payload not VCDM, so it is refused here too. The same
            # holds for the draft-era name and for an absent `typ` (#288, #289): none of them
            # says "IETF SD-JWT VC", so the payload has to say "W3C VC".
            shown = "without a typ" if typ is None else f"typ {typ!r}"
            if not vcdm:
                raise SdJwtError(
                    f"issuer JWT {shown} needs a W3C VCDM @context; an IETF SD-JWT VC "
                    "is typed 'dc+sd-jwt'")
            if typ is None and ("vc" in unpacked or "vp" in unpacked):
                # VC-JOSE-COSE §1.1.2.1, restated in §3.1.3: the claim names `vc` and `vp`
                # MUST NOT be present. A token with a `vc` object and no `typ` would be an
                # SD-JWT VC here and, with its `~` tail dropped, a VC-JWT in the VC-JWT lane.
                # That lane refuses a typed SD-JWT issuer JWT (#189) and, since #291, one
                # whose payload carries an SD-JWT marker, but not a zero-disclosure one with
                # no `typ`: the holder could shed key binding. A token accepted here has no
                # `vc` claim, so that lane refuses its stripped form ("no embedded `vc`
                # object"). The ban cannot help a token this lane never sees; the VC-JWT
                # lane's marker fence (#291) covers that one, and its zero-disclosure
                # residual is documented.
                raise SdJwtError(
                    "issuer JWT without a typ must not carry a `vc` or `vp` claim "
                    "(VC-JOSE-COSE §3.1.3)")
            # A VCDM base URL somewhere in `@context` is enough to enforce the window below
            # (the lax `vcdm`), but not to be read as a credential: the context has to START
            # with it and the `type` has to say credential, whatever the `typ` claims (#275;
            # #293 for an absent `typ`). Without this a payload with no `type`, no `issuer`
            # and a base URL in second place verified as a W3C credential.
            nonconformity = _vcdm_nonconformity(unpacked)
            if nonconformity is not None:
                raise SdJwtError(f"issuer JWT {shown} {nonconformity}")
        vct = unpacked.get("vct")
        if typ == _ISSUER_TYP and not (isinstance(vct, str) and vct):
            # draft-19 §2.2.2.3: `vct` is REQUIRED and never disclosable, so a withheld
            # disclosure of it is detectable: it is absent (like `iss`, without which the
            # issuer JWT never verified at all). §2.2.1: a `dc+sd-jwt` follows these rules
            # whatever else it carries, so a VCDM `@context` does not waive the `vct`
            # (#272); the VCDM window below still applies to it. A `vc+sd-jwt` is a VCDM
            # payload (refused above otherwise), typed by `type` instead.
            raise ClaimsInvalid("an SD-JWT VC (dc+sd-jwt) needs a non-empty string vct")

        # RFC 9901 §7.1 step 6: nbf/exp are checked on the *processed* payload if present.
        # A disclosed `exp`/`nbf` was refused above, so this re-reads the issuer-JWT body's;
        # it still checks a disclosed `iat`, and stays as defence in depth.
        expired = self._check_temporal(unpacked, check_temporal=check_temporal) or expired

        # RFC 7519 §4.1.3 on the issuer JWT's own `aud` (ADR-0008 D4): an issuer that
        # restricted the credential to a relying party is obeyed, whatever the KB-JWT says
        # (its `aud` binds the holder's presentation, not the issuer's restriction). Present
        # only: an issuer JWT without `aud` is the norm and stays as it was. It reads the
        # processed payload: a plaintext `aud` always reaches it (a disclosure can never
        # overwrite a claim), an `aud` the issuer made disclosable is judged once
        # disclosed, and an array whose entries are digests (RFC 9901 §9.7 lets an issuer
        # do that) is judged on the entries the holder disclosed, not as a malformed array.
        # No waiver applies, and the message does not describe an expiry (wiki/SD-JWT-VC.md).
        check_jwt_audience(unpacked, audience, subject="issuer JWT", require_present=False)

        # A W3C credential secured as SD-JWT *is* this claim set (VC-JOSE-COSE §3.2.1), and
        # its `exp` dates the signature, not the data (§3.1.3, JOSE): an issuer may put the
        # expiry only in `validUntil`. Enforce the VCDM window as the VC-JWT lane does — on
        # the processed payload, same leeway, wall clock like `exp`.
        if vcdm:
            expired = check_validity_window(
                unpacked, {}, now=None, leeway_s=self._leeway,
                check_temporal=check_temporal) or expired
            # §4.1.2: `iss`, if present, MUST match `issuer` (or `issuer.id`); §3.1.3 (non-
            # normative) advises the same for `jti`/`id` and `sub`/`credentialSubject.id`.
            # The VC-JWT lane's reconciliation: a present `issuer` names the verified iss.
            VcJwtProofSuite._reconcile({**unpacked, "iss": iss}, unpacked)

        if expected_vct is not None and vct != expected_vct:
            raise ClaimsInvalid(f"vct {vct!r} != expected {expected_vct!r}")
        _check_aka_vcts(unpacked)

        if not require_key_binding:
            key_bound = self._verify_key_binding(
                kb_jwt, issuer_jwt, disclosures, claims.get("cnf"),
                hash_name=hash_name, audience=audience, nonce=nonce,
                required=False, current=current, max_age_s=kb_max_age_s)

        return VerifiedSdJwt(
            claims=unpacked, issuer=iss, vct=vct if isinstance(vct, str) else None,
            key_bound=key_bound, confirmation=claims.get("cnf"), expired=expired,
            vcdm=vcdm, typ=typ)

    # -- internals --------------------------------------------------------- #

    @staticmethod
    def _split(sd_jwt: str) -> tuple[str, list[str], str]:
        """(issuer-jwt, [disclosures], kb-jwt) — kb is '' when absent."""
        parts = sd_jwt.split("~")
        if len(parts) < 2:
            raise MalformedToken("not an SD-JWT (no '~' separator)")
        return parts[0], [p for p in parts[1:-1] if p], parts[-1]

    @staticmethod
    def _decode_jws(jws: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
        """(header, payload, signing_input, signature) for a compact JWS."""
        try:
            header_b64, payload_b64, sig_b64 = jws.split(".")
            header = _json.loads(_b64url_decode(header_b64))
            payload = _json.loads(_b64url_decode(payload_b64))
            signature = _b64url_decode(sig_b64)
        except (ValueError, json.JSONDecodeError, RecursionError) as exc:
            # RecursionError: a deeply-nested (valid) JSON header/payload overruns the
            # interpreter limit; catch it here (the stack has unwound to this frame) and
            # surface it typed, so it never escapes OpenvcError and aborts verify_many.
            raise MalformedToken("not a valid compact JWS") from exc
        if not isinstance(header, dict) or not isinstance(payload, dict):
            # A JOSE header/payload that is valid JSON but not an object (e.g. `[0]`)
            # must fail closed as a typed MalformedToken, never a bare AttributeError
            # on the peek path — which would escape OpenvcError and abort verify_many.
            raise MalformedToken("JWS header and payload must be JSON objects")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return header, payload, signing_input, signature

    @staticmethod
    def _sign_compact(header: dict[str, Any], payload: dict[str, Any], key: SigningKey) -> str:
        signing_input = (
            f"{_b64url_encode(_json_bytes(header))}.{_b64url_encode(_json_bytes(payload))}")
        signature = key.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url_encode(signature)}"

    @staticmethod
    def _verify_signature(
        alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes, *, what: str
    ) -> None:
        try:
            ok = verify_signature(
                alg=alg, public_jwk=jwk, signing_input=signing_input, signature=signature)
        except KeyBackendError as exc:
            raise ProofError(f"could not verify {what}: {exc}") from exc
        if not ok:
            raise SignatureInvalid(f"{what} signature failed")

    def _check_temporal(
        self, claims: dict[str, Any], *, check_temporal: bool = True
    ) -> bool:
        # NumericDate exp/nbf/iat, fail-closed (null, NaN, strings and bignums rejected)
        # and a future iat bounded, single-sourced across the JOSE suites
        # (openvc.proof._verify_common.check_jwt_temporal). Runs on the issuer-JWT body
        # and again on the unpacked claims, where a disclosed iat first appears. True
        # when a waived exp has passed.
        return check_jwt_temporal(
            claims, leeway_s=self._leeway, subject="token",
            check_temporal=check_temporal)

    def _index_disclosures(self, disclosures: list[str], hash_name: str) -> dict[str, list]:
        by_digest: dict[str, list] = {}
        for disclosure in disclosures:
            try:
                parsed = _json.loads(_b64url_decode(disclosure))
            except (ValueError, json.JSONDecodeError, RecursionError) as exc:
                raise SdJwtError("a disclosure is not valid base64url JSON") from exc
            if not isinstance(parsed, list) or len(parsed) not in (2, 3):
                raise SdJwtError("a disclosure must be a 2- or 3-element array")
            digest = disclosure_digest(disclosure, hash_name=hash_name)
            if digest in by_digest:
                raise SdJwtError("duplicate disclosure in presentation")
            by_digest[digest] = parsed
        return by_digest

    def _verify_key_binding(
        self,
        kb_jwt: str,
        issuer_jwt: str,
        disclosures: list[str],
        cnf: Any,
        *,
        hash_name: str,
        audience: str | None,
        nonce: str | None,
        required: bool,
        current: float,
        max_age_s: int,
    ) -> bool:
        if required and (audience is None or nonce is None):
            # A KB-JWT proves possession of the holder key and that these disclosures were
            # presented, but only the aud+nonce bind it to THIS verifier and challenge.
            # Requiring key binding without supplying them gives no replay protection —
            # a presentation built for verifier A would satisfy verifier B. Fail closed,
            # matching VP-JWT's "no unbound mode".
            raise ClaimsInvalid(
                "key binding required but no audience/nonce given to bind it against "
                "(a KB-JWT without a verifier nonce and aud does not prevent replay)")
        if not kb_jwt:
            if required:
                raise ClaimsInvalid("key binding required but no KB-JWT present")
            return False
        if audience is not None or nonce is not None:
            # RFC 9901 §7.3 step 5.6 binds a KB-JWT by aud AND nonce: aud alone lets a
            # KB-JWT from another of this verifier's sessions replay, nonce alone lets one
            # made for another verifier relay. Checking only the value given would report
            # key_bound=True for a binding that never happened, so a half-configured
            # caller fails closed here, before any KB-JWT crypto. Only with a KB-JWT
            # present: `audience` alone is a valid VC-JWT policy, and an SD-JWT without a
            # KB-JWT honestly reports key_bound=False.
            if audience is None or nonce is None:
                given = "audience" if nonce is None else "nonce"
                raise ClaimsInvalid(
                    f"a KB-JWT is present but only {given} was given to bind it against; "
                    "aud and nonce bind it together (RFC 9901 §7.3 step 5.6), so pass both")
            # An empty (or non-string) value binds nothing: `nonce=""` from a lost session
            # would accept any KB-JWT the holder signed with an empty nonce. Every other
            # binding gate (VP-JWT, OpenID4VP, the nested _kb_binding) refuses it too.
            if not (isinstance(audience, str) and audience
                    and isinstance(nonce, str) and nonce):
                raise ClaimsInvalid(
                    "the audience and nonce a KB-JWT is bound against must be non-empty "
                    "strings")
        header, claims, signing_input, signature = self._decode_jws(kb_jwt)
        if header.get("typ") != _KB_TYP:
            raise SdJwtError(f"KB-JWT typ must be {_KB_TYP!r}")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._algs:     # unhashable-safe
            raise UnsupportedAlgorithm(
                f"KB-JWT algorithm {safe_repr(alg)} is not permitted")
        reject_unknown_crit(header)
        if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
            raise ClaimsInvalid("no cnf.jwk in the issuer JWT for key binding")
        self._verify_signature(alg, cnf["jwk"], signing_input, signature, what="KB-JWT")

        # RFC 9901 §4.3: `iat` is REQUIRED; §7.3 step 5.5: within an acceptable window.
        # The nonce binds a KB-JWT to one transaction, but only the caller knows how old
        # that nonce is — this window is the freshness bound a stateless verifier owns.
        check_iat_freshness(
            claims.get("iat"), max_age_s=max_age_s, leeway_s=self._leeway,
            current=current, subject="KB-JWT")
        # RFC 9901 defines no exp/nbf on a KB-JWT, but a signed one is not ignored: same
        # shape rule as the issuer JWT, evaluated at the same `current` as the iat window.
        # A window failure is a binding failure, phrased without "expired": callers read
        # an `expired` ClaimsInvalid from a required-binding verify as "bound, but the
        # issuer JWT expired" (wiki/SD-JWT-VC.md), and no waiver applies here.
        check_numeric_dates(claims, "exp", "nbf", subject="KB-JWT")
        try:
            check_jwt_temporal(claims, leeway_s=self._leeway, subject="KB-JWT",
                               now=current)
        except ClaimsInvalid as exc:
            raise ClaimsInvalid("KB-JWT is outside its own exp/nbf window") from exc
        if audience is not None and claims.get("aud") != audience:
            raise ClaimsInvalid("KB-JWT aud does not match")
        if nonce is not None and claims.get("nonce") != nonce:
            raise ClaimsInvalid("KB-JWT nonce does not match")
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        expected = _b64url_encode(_HASHES[hash_name](_ascii_bytes(presented)).digest())
        if claims.get("sd_hash") != expected:
            raise ClaimsInvalid("KB-JWT sd_hash does not match the presented disclosures")
        return True


__all__ = [
    "DEFAULT_KB_MAX_AGE_S",
    "SdJwtError",
    "SdJwtVcProofSuite",
    "VerifiedSdJwt",
    "disclosure_digest",
    "make_array_disclosure",
    "make_object_disclosure",
]
