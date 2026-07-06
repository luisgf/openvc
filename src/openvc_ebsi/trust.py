"""
openvc_ebsi.trust — recursive EBSI trust-chain verification.

Walk an issuer up the accreditation chain (``TI -> TAO -> ... -> RootTAO``),
verifying at each hop that the accreditation is a real, non-revoked VC-JWT signed
by the accreditor it names, until the chain reaches a **trusted RootTAO anchor**.

Trust is relative to the anchors YOU choose — the RootTAO DIDs you decide to
trust. There is no implicit root: an empty anchor set trusts nobody. This keeps
the library honest about where trust actually comes from.

What each hop checks (defence in depth):

  * **Delegation scoping.** The leaf must be accredited for (at least one of) the
    credential's types; the intersection becomes the *delegated scope*. Every
    accreditor above it must be accredited for a **superset** of that scope — a
    TAO cannot vouch for a type it was never authorised to accredit.
  * **Signature & identity.** The accreditation VC-JWT's ``iss`` equals the
    ``accreditedBy`` DID it names, its signature verifies against that
    accreditor's *resolved* key, and its subject is the DID being accredited.
  * **Revocation (optional).** With a ``resolve_status_list`` the accreditation's
    own ``credentialStatus`` is checked too — a revoked accreditation breaks the
    chain, not just a TIR ``revoked`` role.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openvc.did.base import DidResolutionError
from openvc.proof.errors import ProofError
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import ResolveStatusList, check_credential_status

from .errors import EbsiError
from .http import HttpNotFound
from .models import Accreditation, IssuerRecord
from .versioning import DidEbsiResolver

DEFAULT_MAX_DEPTH = 6


class TrustChainError(EbsiError): ...
class NoTrustedAnchor(TrustChainError): ...
class AccreditationInvalid(TrustChainError): ...
class AccreditationRevoked(TrustChainError): ...


@dataclass(frozen=True)
class TrustHop:
    subject: str                 # the DID accredited at this hop
    accreditor: str              # the DID that issued (and signed) the accreditation
    accreditation: Accreditation


@dataclass(frozen=True)
class TrustChain:
    subject: str                 # the leaf issuer the walk started from
    anchor: str                  # the trusted RootTAO the chain terminated at
    hops: tuple[TrustHop, ...]   # leaf -> ... -> anchor, in order
    scope: frozenset[str]        # the delegated credential types the chain vouches for


def _pick_accreditation(
    record: IssuerRecord, needed: set[str], *, leaf: bool
) -> Accreditation | None:
    """A non-revoked accreditation authorising *needed*.

    At the leaf its ``accreditedFor`` must **intersect** *needed* (the issuer is
    authorised for at least one of the credential's types); above the leaf it
    must be a **superset** of the delegated scope (the accreditor can delegate
    everything beneath it).
    """
    if not record.has_attributes:
        return None
    for acc in record.accreditations:
        if acc.is_revoked:
            continue
        authorised = set(acc.credential_types)
        if leaf:
            if authorised & needed:
                return acc
        elif needed <= authorised:
            return acc
    return None


def _verify_accreditation(
    acc: Accreditation, *, subject: str, accreditor: str,
    resolver: DidEbsiResolver, proof_suite: VcJwtProofSuite,
) -> dict[str, Any]:
    """Verify the accreditation VC-JWT was signed by *accreditor* and issued for
    *subject*; return its verified credential (the ``vc`` object). Raises
    :class:`AccreditationInvalid` on any inconsistency."""
    if not acc.credential_jwt:
        raise AccreditationInvalid(
            f"no raw accreditation token for {subject!r}; cannot verify its proof")

    iss, kid = proof_suite.peek_issuer(acc.credential_jwt)
    if iss != accreditor:
        raise AccreditationInvalid(
            f"accreditation issuer {iss!r} != accreditedBy {accreditor!r}")

    try:
        doc = resolver.resolve(accreditor)
    except DidResolutionError as exc:
        raise AccreditationInvalid(
            f"cannot resolve accreditor {accreditor!r}: {exc}") from exc
    vm = doc.key_by_kid(kid)
    if vm is None:
        raise AccreditationInvalid(
            f"no verification method {kid!r} for accreditor {accreditor!r}")

    try:
        verified = proof_suite.verify(acc.credential_jwt, public_key_jwk=vm.public_key_jwk)
    except ProofError as exc:
        raise AccreditationInvalid(
            f"accreditation for {subject!r} failed verification: {exc}") from exc

    if verified.subject and verified.subject != subject:
        raise AccreditationInvalid(
            f"accreditation subject {verified.subject!r} != accredited DID {subject!r}")
    return verified.credential


def verify_trust_chain(
    subject_did: str,
    credential_types: list[str],
    *,
    resolver: DidEbsiResolver,
    proof_suite: VcJwtProofSuite,
    anchors: set[str],
    max_depth: int = DEFAULT_MAX_DEPTH,
    resolve_status_list: ResolveStatusList | None = None,
) -> TrustChain:
    """Walk ``subject_did`` up to a trusted RootTAO in *anchors*.

    Returns the verified :class:`TrustChain` on success; raises
    :class:`NoTrustedAnchor` (no reachable anchor / no accreditation for the
    delegated scope), :class:`AccreditationInvalid` (a bad signature/identity on
    the path), or :class:`AccreditationRevoked` (an accreditation revoked via its
    own status list, when *resolve_status_list* is given).
    """
    if subject_did in anchors:                       # the leaf is itself an anchor
        return TrustChain(subject=subject_did, anchor=subject_did, hops=(),
                          scope=frozenset(credential_types))

    hops: list[TrustHop] = []
    current = subject_did
    seen = {current}
    scope: set[str] | None = None                    # delegated types, fixed at the leaf

    for _ in range(max_depth):
        try:
            record = resolver.issuer_record(current)
        except HttpNotFound as exc:
            # An accreditor absent from the TIR breaks the chain — not trusted,
            # rather than a leaked 404. (At the leaf, the issuer isn't registered.)
            raise NoTrustedAnchor(
                f"{current!r} is not in the Trusted Issuers Registry") from exc

        is_leaf = scope is None
        needed = set(credential_types) if is_leaf else scope
        assert needed is not None
        acc = _pick_accreditation(record, needed, leaf=is_leaf)
        if acc is None:
            raise NoTrustedAnchor(
                f"{current!r} has no valid accreditation for "
                + ("the credential's types" if is_leaf
                   else f"the delegated types {sorted(needed)}"))

        accreditor = acc.tao
        if not accreditor:
            raise AccreditationInvalid(
                f"accreditation for {current!r} names no accreditor (accreditedBy)")

        vc = _verify_accreditation(acc, subject=current, accreditor=accreditor,
                                   resolver=resolver, proof_suite=proof_suite)
        if resolve_status_list is not None:
            status = check_credential_status(vc, resolve_status_list=resolve_status_list)
            if status.revoked:
                raise AccreditationRevoked(
                    f"the accreditation for {current!r} is revoked via its status list")

        if is_leaf:                                  # fix the delegated scope
            scope = set(acc.credential_types) & set(credential_types)
        hops.append(TrustHop(subject=current, accreditor=accreditor, accreditation=acc))

        if accreditor in anchors:                    # reached the trust root
            return TrustChain(subject=subject_did, anchor=accreditor,
                              hops=tuple(hops), scope=frozenset(scope or ()))
        if accreditor in seen:
            raise TrustChainError(f"accreditation cycle detected at {accreditor!r}")

        seen.add(accreditor)
        current = accreditor

    raise NoTrustedAnchor(
        f"no trusted anchor within {max_depth} hops from {subject_did!r}")
