"""
openvc_ebsi.trust — recursive EBSI trust-chain verification.

Walk an issuer up the accreditation chain (``TI -> TAO -> ... -> RootTAO``),
verifying at each hop that the accreditation is a real, non-revoked VC-JWT signed
by the accreditor it names, until the chain reaches a **trusted RootTAO anchor**.

Trust is relative to the anchors YOU choose — the RootTAO DIDs you decide to
trust. There is no implicit root: an empty anchor set trusts nobody. This keeps
the library honest about where trust actually comes from.

What each hop checks (defence in depth):

  * a non-revoked accreditation exists (authorising the credential's types at the
    first hop; any non-revoked accreditation at higher hops — per-hop type
    scoping is a documented refinement);
  * the accreditation VC-JWT's ``iss`` equals the ``accreditedBy`` DID it claims;
  * that VC-JWT's signature verifies against the accreditor's *resolved* key;
  * the accreditation's subject is the DID being accredited at this hop.

Not yet covered (see docs/ROADMAP.md): status-list revocation of the
accreditations themselves, and strict per-hop ``accreditedFor`` delegation
subset checks.
"""
from __future__ import annotations

from dataclasses import dataclass

from openvc.did.base import DidResolutionError
from openvc.proof.vc_jwt import ProofError, VcJwtProofSuite

from .http import HttpNotFound
from .models import Accreditation, IssuerRecord
from .versioning import DidEbsiResolver

DEFAULT_MAX_DEPTH = 6


class TrustChainError(Exception): ...
class NoTrustedAnchor(TrustChainError): ...
class AccreditationInvalid(TrustChainError): ...


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


def _pick_accreditation(
    record: IssuerRecord, credential_types: list[str] | None
) -> Accreditation | None:
    """First non-revoked accreditation that authorises the wanted types (or any
    non-revoked one when *credential_types* is None, for higher hops)."""
    if not record.has_attributes:
        return None
    wanted = set(credential_types) if credential_types is not None else None
    for acc in record.accreditations:
        if acc.is_revoked:
            continue
        if wanted is None:
            return acc
        if not acc.credential_types or (wanted & set(acc.credential_types)):
            return acc
    return None


def _verify_accreditation(
    acc: Accreditation, *, subject: str, accreditor: str,
    resolver: DidEbsiResolver, proof_suite: VcJwtProofSuite,
) -> None:
    """Verify the accreditation VC-JWT was signed by *accreditor* and issued for
    *subject*. Raises :class:`AccreditationInvalid` on any inconsistency."""
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


def verify_trust_chain(
    subject_did: str,
    credential_types: list[str],
    *,
    resolver: DidEbsiResolver,
    proof_suite: VcJwtProofSuite,
    anchors: set[str],
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> TrustChain:
    """Walk ``subject_did`` up to a trusted RootTAO in *anchors*.

    Returns the verified :class:`TrustChain` on success; raises
    :class:`NoTrustedAnchor` if no anchor is reached within *max_depth* hops (or
    the issuer has no usable accreditation), or :class:`AccreditationInvalid` if
    any accreditation on the path fails its signature/consistency checks.
    """
    if subject_did in anchors:                       # the leaf is itself an anchor
        return TrustChain(subject=subject_did, anchor=subject_did, hops=())

    hops: list[TrustHop] = []
    current = subject_did
    seen = {current}
    # Only the leaf hop is scoped to the credential's types; higher hops just
    # need to be accredited (registered + non-revoked).
    wanted: list[str] | None = credential_types

    for _ in range(max_depth):
        try:
            record = resolver.issuer_record(current)
        except HttpNotFound as exc:
            # An accreditor absent from the TIR breaks the chain — not trusted,
            # rather than a leaked 404. (At the leaf, the issuer isn't registered.)
            raise NoTrustedAnchor(
                f"{current!r} is not in the Trusted Issuers Registry") from exc
        acc = _pick_accreditation(record, wanted)
        if acc is None:
            raise NoTrustedAnchor(
                f"{current!r} has no valid accreditation"
                + (f" for types {wanted}" if wanted is not None else ""))

        accreditor = acc.tao
        if not accreditor:
            raise AccreditationInvalid(
                f"accreditation for {current!r} names no accreditor (accreditedBy)")

        _verify_accreditation(acc, subject=current, accreditor=accreditor,
                              resolver=resolver, proof_suite=proof_suite)
        hops.append(TrustHop(subject=current, accreditor=accreditor, accreditation=acc))

        if accreditor in anchors:                    # reached the trust root
            return TrustChain(subject=subject_did, anchor=accreditor, hops=tuple(hops))
        if accreditor in seen:
            raise TrustChainError(f"accreditation cycle detected at {accreditor!r}")

        seen.add(accreditor)
        current = accreditor
        wanted = None                                # higher hops: any accreditation

    raise NoTrustedAnchor(
        f"no trusted anchor within {max_depth} hops from {subject_did!r}")
