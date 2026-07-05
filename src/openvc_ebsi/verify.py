"""
openvc_ebsi.verify — the end-to-end verify_ebsi_badge glue.

Wires the pieces the other modules expose into one call:

    peek issuer/kid (UNTRUSTED, just to select a key)
      -> resolve the DID document       (DID Registry adapter)
      -> select the verification method  (by kid)
      -> verify signature + temporal claims + VC-JWT reconciliation (proof suite)
      -> check issuer trust in the TIR   (a non-revoked accreditation for the type)

Scope, stated honestly:

* **Trust is single-level here.** It confirms the *issuer itself* holds a valid,
  non-revoked accreditation authorising the credential's type(s). The recursive
  ``TI -> TAO -> RootTAO`` walk up to a trusted anchor is the next step (the
  domain model already carries ``tao``/``root_tao`` for it) — see docs/ROADMAP.md.
* **Revocation of the credential** (status list) is not checked yet; it waits on
  the ``openvc/status`` package. This verifies signature + issuer trust only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openvc.did.base import DidResolutionError
from openvc.proof.vc_jwt import VcJwtProofSuite, VerifiedCredential
from openvc.status import (
    CredentialRevoked,
    ResolveStatusList,
    StatusResult,
    check_credential_status,
)

from .models import Accreditation, IssuerRecord
from .trust import TrustChain, TrustChainError, verify_trust_chain
from .versioning import DidEbsiResolver


class EbsiVerificationError(Exception): ...
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

    Single-level policy, fail-closed: pick the first **non-revoked** accreditation
    that either authorises one of the credential's types, or carries no type
    restriction at all. An accreditation scoped to other types does not count.
    """
    if not record.has_attributes:
        return None
    wanted = set(credential_types)
    for acc in record.accreditations:
        if acc.is_revoked:
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
      a non-revoked accreditation for the credential's types.
    * ``trust_anchors`` **given** — the full recursive chain is walked and every
      accreditation's signature verified, up to a trusted RootTAO in that set.

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
            f"could not resolve issuer DID {issuer_hint!r}: {exc}") from exc
    vm = doc.key_by_kid(kid)
    if vm is None:
        raise VerificationMethodNotFound(
            f"no verification method for kid {kid!r} in DID {issuer_hint!r}")

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
        record = resolver.issuer_record(verified.issuer)
        accreditation = evaluate_issuer_trust(record, cred_types)
        trusted = accreditation is not None
        if require_trust and not trusted:
            raise IssuerNotTrusted(
                f"issuer {verified.issuer!r} has no valid accreditation for "
                f"types {cred_types}")

    # 6) revocation — a set revocation bit invalidates the credential outright.
    status: StatusResult | None = None
    if resolve_status_list is not None:
        status = check_credential_status(
            verified.credential, resolve_status_list=resolve_status_list)
        if status.revoked:
            raise CredentialRevoked(
                f"credential {verified.credential.get('id')!r} is revoked")

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
