"""
openvc.verify — the generic verification pipeline.

One call, :func:`verify_credential`, that

  1. **detects the format** — VC-JWT, SD-JWT VC, Data Integrity (eddsa-rdfc-2022 /
     ecdsa-sd-2023), or an enveloped VCDM 2.0 credential;
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
:class:`~openvc.proof.vc_jwt.ProofError` subclass (shared by every suite); a
pipeline-level failure (unknown format, key resolution, type mismatch, missing
status resolver) raises a :class:`VerificationError` subclass; a revoked
credential raises :class:`~openvc.status.CredentialRevoked`.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence, Union

from .proof._verify_common import DEFAULT_LEEWAY_S
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
FORMAT_ENVELOPED = "enveloped-verifiable-credential"

_CRYPTOSUITE_FORMAT = {
    "eddsa-rdfc-2022": FORMAT_DI_EDDSA,
    "ecdsa-sd-2023": FORMAT_DI_ECDSA_SD,
}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class VerificationError(Exception):
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
    declares a status but is verified without a resolver is rejected. ``now``
    pins the evaluation instant for Data Integrity temporal checks (the JOSE
    suites use the current time)."""
    leeway_s: int = DEFAULT_LEEWAY_S
    expected_types: Sequence[str] | None = None
    expected_vct: str | None = None
    audience: str | None = None
    nonce: str | None = None
    require_key_binding: bool = False
    proof_purpose: str = "assertionMethod"
    require_status: bool = True
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
    raw: Any = None                            # the underlying suite result


# --------------------------------------------------------------------------- #
# Default resolver
# --------------------------------------------------------------------------- #

def default_resolver():
    """A :class:`DidResolverRegistry` with the offline ``did:key`` resolver and the
    SSRF-guarded ``did:web`` resolver — the pipeline's default when none is passed.
    (``did:web`` only reaches the network when a ``did:web`` DID is resolved.)"""
    from .did.base import DidResolverRegistry
    from .did.did_key import DidKeyResolver
    from .fetch import default_did_web_resolver
    return DidResolverRegistry([DidKeyResolver(), default_did_web_resolver()])


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
    extra_contexts: Any = None,
    _depth: int = 0,
) -> VerificationResult:
    """Verify a credential in any supported format against *policy*.

    *resolver* (a ``DidResolver`` / ``DidResolverRegistry``) resolves the issuer
    key; it defaults to :func:`default_resolver` (offline ``did:key`` +
    SSRF-guarded ``did:web``). *resolve_status_list* fetches and **verifies** a W3C
    status-list credential (for VC-JWT / Data Integrity); *resolve_status_list_token*
    does the same for an IETF status-list token (SD-JWT). *extra_contexts* is passed
    to the Data Integrity canonicaliser for offline non-bundled contexts.
    """
    policy = policy or VerificationPolicy()
    resolver = resolver if resolver is not None else default_resolver()

    fmt = detect_format(credential)

    if fmt == FORMAT_ENVELOPED:
        if _depth >= 2:
            raise UnknownCredentialFormat("enveloped credential nested too deeply")
        return verify_credential(
            _unwrap_enveloped(credential), policy=policy, resolver=resolver,
            resolve_status_list=resolve_status_list,
            resolve_status_list_token=resolve_status_list_token,
            extra_contexts=extra_contexts, _depth=_depth + 1)

    if fmt == FORMAT_VC_JWT:
        return _verify_vc_jwt(
            credential, policy, resolver, resolve_status_list, resolve_status_list_token)
    if fmt == FORMAT_SD_JWT_VC:
        return _verify_sd_jwt(
            credential, policy, resolver, resolve_status_list, resolve_status_list_token)
    return _verify_data_integrity(
        credential, fmt, policy, resolver, resolve_status_list,
        resolve_status_list_token, extra_contexts)


# -- per-format handlers ---------------------------------------------------- #

def _verify_vc_jwt(token, policy, resolver, resolve_status_list,
                   resolve_status_list_token) -> VerificationResult:
    from .proof.vc_jwt import VcJwtProofSuite

    suite = VcJwtProofSuite(leeway_s=policy.leeway_s)
    iss, kid = suite.peek_issuer(token)
    jwk = _resolve_jose_key(resolver, iss, kid)
    verified = suite.verify(token, public_key_jwk=jwk, audience=policy.audience)
    _check_types(verified.credential, policy.expected_types)
    # W3C status is in the vc object; an IETF `status` claim is in the JWT payload
    status = _check_status(verified.credential, verified.claims, policy,
                           resolve_status_list, resolve_status_list_token)
    return VerificationResult(
        format=FORMAT_VC_JWT, credential=verified.credential, claims=verified.claims,
        issuer=verified.issuer, subject=verified.subject, status=status, raw=verified)


def _verify_sd_jwt(sd_jwt, policy, resolver, resolve_status_list,
                   resolve_status_list_token) -> VerificationResult:
    from .proof.sd_jwt import SdJwtVcProofSuite

    suite = SdJwtVcProofSuite(leeway_s=policy.leeway_s)
    iss, kid = suite.peek_issuer(sd_jwt)
    jwk = _resolve_jose_key(resolver, iss, kid)
    verified = suite.verify(
        sd_jwt, public_key_jwk=jwk, audience=policy.audience, nonce=policy.nonce,
        require_key_binding=policy.require_key_binding, expected_vct=policy.expected_vct)
    # the disclosed claims may carry either a W3C credentialStatus or an IETF status
    status = _check_status(verified.claims, verified.claims, policy,
                           resolve_status_list, resolve_status_list_token)
    return VerificationResult(
        format=FORMAT_SD_JWT_VC, credential=verified.claims, claims=verified.claims,
        issuer=verified.issuer, subject=_as_str(verified.claims.get("sub")),
        key_bound=verified.key_bound, status=status, raw=verified)


def _verify_data_integrity(
    doc, fmt, policy, resolver, resolve_status_list, resolve_status_list_token,
    extra_contexts,
) -> VerificationResult:
    if fmt == FORMAT_DI_ECDSA_SD:
        from .proof.ecdsa_sd import EcdsaSdProofSuite
        suite: Any = EcdsaSdProofSuite(leeway_s=policy.leeway_s)
    else:
        from .proof.data_integrity import DataIntegrityProofSuite
        suite = DataIntegrityProofSuite(leeway_s=policy.leeway_s)

    verified = suite.verify(
        doc, resolver=resolver, expected_proof_purpose=policy.proof_purpose,
        now=policy.now, extra_contexts=extra_contexts)
    _bind_issuer_to_verification_method(verified)
    _check_types(verified.credential, policy.expected_types)
    # DI credentials use W3C credentialStatus, but pass the doc as the IETF source
    # too so a (non-conformant) token `status` on one is not silently skipped
    status = _check_status(verified.credential, verified.credential, policy,
                           resolve_status_list, resolve_status_list_token)
    return VerificationResult(
        format=fmt, credential=verified.credential, issuer=verified.issuer,
        subject=verified.subject, status=status, raw=verified)


# -- shared helpers --------------------------------------------------------- #

def _resolve_jose_key(resolver: Any, iss: str, kid: str | None) -> dict[str, Any]:
    from .did.base import DidError
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


def _fail_closed(policy: VerificationPolicy, declared: str, resolver_arg: str) -> None:
    """Raise (fail-closed) when a status is declared but its resolver is missing,
    unless the caller opted out via ``require_status=False``."""
    if policy.require_status:
        raise StatusUnavailable(
            f"credential declares a {declared} but no {resolver_arg} was given "
            "(set policy.require_status=False to skip)")


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None
