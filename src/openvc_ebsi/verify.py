"""
openvc_ebsi.verify — the end-to-end verify_ebsi_badge glue.

Wires the pieces the other modules expose into one call:

    peek issuer/kid (UNTRUSTED, just to select a key)
      -> resolve the DID document       (DID Registry adapter)
      -> select the verification method  (by kid)
      -> verify signature + temporal claims + VC-JWT reconciliation (proof suite)
      -> check issuer trust in the TIR   (a live-role accreditation for the type)

Trust has two modes (see ``verify_ebsi_badge``):

* **Single level** (default) — the *issuer itself* must hold a valid accreditation
  with a live role (``RootTAO``, ``TAO`` or ``TI``, never ``Revoked``) authorising the
  credential's type(s).
* **Recursive** (pass ``trust_anchors``) — the full ``TI -> TAO -> RootTAO`` chain
  is walked and every accreditation's signature verified, up to a trusted anchor
  (:mod:`openvc_ebsi.trust`).

Credential revocation is checked too when a ``resolve_status_list`` is supplied
(a set revocation bit raises :class:`~openvc.status.CredentialRevoked`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openvc.did.base import DidResolutionError
from openvc.proof._verify_common import safe_repr
from openvc.proof.vc_jwt import VcJwtProofSuite, VerifiedCredential
from openvc.status import (
    CredentialRevoked,
    ResolveStatusList,
    StatusResult,
    check_credential_status,
)

from ._message import bounded_text, url_repr
from .errors import EbsiError
from .models import Accreditation, IssuerRecord
from .trust import TrustChain, TrustChainError, ineligible_roles_note, verify_trust_chain
from .versioning import DidEbsiResolver


class EbsiVerificationError(EbsiError): ...
class VerificationMethodNotFound(EbsiVerificationError): ...
class IssuerNotTrusted(EbsiVerificationError): ...


@dataclass(frozen=True)
class VerifiedEbsiBadge:
    """The result of a successful (or trust-optional) EBSI verification.

    In single-level mode (no ``trust_anchors``) ``issuer_record`` +
    ``accreditation`` describe the check and ``chain`` is None. In recursive mode
    (``trust_anchors`` given) ``chain`` carries the full verified path and
    ``accreditation`` is the leaf hop's; ``issuer_record`` is None (the chain is
    the richer artifact).
    """
    credential: dict[str, Any]
    issuer: str
    subject: str | None
    trusted: bool                          # issuer holds a valid accreditation
    accreditation: Accreditation | None    # the one that granted trust, if any
    issuer_record: IssuerRecord | None
    verified: VerifiedCredential           # the raw proof-suite result
    chain: TrustChain | None = None        # the recursive path, if walked
    status: StatusResult | None = None     # revocation check, if resolve given


def _credential_types(credential: dict[str, Any]) -> list[str]:
    t = credential.get("type", [])
    if isinstance(t, str):
        return [t]
    return [x for x in t if isinstance(x, str)]


def evaluate_issuer_trust(
    record: IssuerRecord, credential_types: list[str]
) -> Accreditation | None:
    """Return the accreditation that authorises this issuer for the credential,
    or ``None`` if untrusted.

    Single-level policy, fail-closed: pick the first accreditation whose ``issuerType`` is
    exactly a live role (``RootTAO``, ``TAO`` or ``TI``; #358) that either authorises one of
    the credential's types, or carries no type restriction at all. ``Revoked`` (the spelling
    both registry APIs use), ``undefined``, an absent member and any other string are set
    aside, and an accreditation scoped to other types does not count.
    """
    if not record.has_attributes:
        return None
    wanted = set(credential_types)
    for acc in record.accreditations:
        if not acc.has_trust_role:                 # Revoked, undefined, absent, misspelt (#358)
            continue
        if not acc.credential_types:               # unrestricted accreditation
            return acc
        if wanted & set(acc.credential_types):     # authorises a wanted type
            return acc
    return None


def verify_ebsi_badge(
    token: str,
    *,
    resolver: DidEbsiResolver,
    proof_suite: VcJwtProofSuite,
    expected_types: list[str] | None = None,
    require_trust: bool = True,
    trust_anchors: set[str] | None = None,
    resolve_status_list: ResolveStatusList | None = None,
    audience: str | None = None,
) -> VerifiedEbsiBadge:
    """Verify an EBSI-issued VC-JWT badge end to end.

    ``expected_types`` (if given) are asserted present in the credential.

    Trust modes:

    * ``trust_anchors`` **omitted** — single-level check: the issuer itself holds
      an accreditation with a live role (not ``Revoked``) for the credential's types.
    * ``trust_anchors`` **given** — the full recursive chain is walked and every
      accreditation's signature verified, up to a trusted RootTAO in that set.

    ``proof_suite`` is ONE suite for the leaf badge and for every accreditation hop of the
    chain, so ``VcJwtProofSuite(allow_es256k=True)`` (the opt-in a Core API v1 RootTAO needs)
    also admits an ES256K-signed leaf badge; there is no separate suite for the hops.

    ``require_trust`` controls only whether an untrusted result raises (single
    level: :class:`IssuerNotTrusted`; recursive: a
    :class:`~openvc_ebsi.trust.TrustChainError`) or is returned with
    ``trusted=False``.

    ``resolve_status_list`` (if given) enables revocation checking: it must fetch
    and **verify** a status-list credential URL and return it as a dict. A set
    revocation bit raises :class:`~openvc.status.CredentialRevoked` regardless of
    ``require_trust`` — a revoked credential is invalid. The check runs only after
    the signature verifies.
    """
    # 1) select the key to resolve (UNTRUSTED peek).
    issuer_hint, kid = proof_suite.peek_issuer(token)

    # 2) resolve the issuer DID and (3) pick the verification method.
    try:
        doc = resolver.resolve(issuer_hint)
    except DidResolutionError as exc:
        raise EbsiVerificationError(
            f"could not resolve issuer DID {safe_repr(issuer_hint)}: {exc}") from exc
    vm = doc.key_by_kid(kid)
    if vm is None:
        raise VerificationMethodNotFound(
            f"no verification method for kid {safe_repr(kid)} in DID {safe_repr(issuer_hint)}")

    # 4) verify signature + temporal claims + envelope reconciliation.
    verified = proof_suite.verify(
        token, public_key_jwk=vm.public_key_jwk,
        expected_types=expected_types, audience=audience)

    # 5) issuer trust — recursive chain if anchors were supplied, else single level.
    cred_types = _credential_types(verified.credential)
    chain: TrustChain | None = None
    record: IssuerRecord | None = None
    if trust_anchors is not None:
        try:
            chain = verify_trust_chain(
                verified.issuer, cred_types, resolver=resolver,
                proof_suite=proof_suite, anchors=trust_anchors,
                resolve_status_list=resolve_status_list)
        except TrustChainError:
            if require_trust:
                raise
            chain = None
        trusted = chain is not None
        accreditation = chain.hops[0].accreditation if (chain and chain.hops) else None
    else:
        try:
            record = resolver.issuer_record(verified.issuer)
        except DidResolutionError as exc:
            # `verified.issuer` was resolved in step 2, so this cannot be reached from a
            # token; it is wrapped because `issuer_record` is public (#266). A
            # MalformedRegistryResponse (a record that is not about the issuer, #267)
            # is not caught: it is malformed input, not an untrusted issuer.
            raise EbsiVerificationError(
                f"could not read the registry record of issuer "
                f"{safe_repr(verified.issuer)}: {exc}") from exc
        accreditation = evaluate_issuer_trust(record, cred_types)
        trusted = accreditation is not None
        if require_trust and not trusted:
            # both are the credential's own claims, and a 70 000-character `type` entry (or a
            # list of that many) made the message as long (#351)
            raise IssuerNotTrusted(
                f"issuer {safe_repr(verified.issuer)} has no valid accreditation for "
                f"types {bounded_text(cred_types)}"
                + ineligible_roles_note(record, leaf=True))

    # 6) revocation — a set revocation bit invalidates the credential outright.
    status: StatusResult | None = None
    if resolve_status_list is not None:
        status = check_credential_status(
            verified.credential, resolve_status_list=resolve_status_list)
        if status.revoked:
            cred_id = verified.credential.get("id")    # never repr() a hostile shape
            raise CredentialRevoked(
                f"credential {url_repr(cred_id if isinstance(cred_id, str) else None)} "
                "is revoked")

    return VerifiedEbsiBadge(
        credential=verified.credential,
        issuer=verified.issuer,
        subject=verified.subject,
        trusted=trusted,
        accreditation=accreditation,
        issuer_record=record,
        verified=verified,
        chain=chain,
        status=status,
    )
