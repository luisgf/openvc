"""
openvc_ebsi.trust — recursive EBSI trust-chain verification.

Walk an issuer up the accreditation chain (``TI -> TAO -> ... -> RootTAO``),
verifying at each hop that the accreditation is a real, non-revoked VC-JWT signed
by the accreditor it names, until the chain reaches a **trusted RootTAO anchor**.

Trust is relative to the anchors YOU choose — the RootTAO DIDs you decide to
trust. There is no implicit root: an empty anchor set trusts nobody. This keeps
the library honest about where trust actually comes from.

**Algorithms.** The *proof_suite* you pass decides which accreditation signatures can be
verified, at every hop. EBSI Core API v1 signs its RootTAO accreditation JWTs ``ES256K``
(RFC 8812), which the default allow-list refuses: with a default suite a walk that reaches such
a root raises :class:`AccreditationInvalid` (its cause is ``UnsupportedAlgorithm``). Pass
``VcJwtProofSuite(allow_es256k=True)`` to verify them; it is a verification-only opt-in and
changes nothing else (ADR-0009, open question 3). One suite serves the leaf badge and the hops.
The prod seed root has no verification method in its DID document, so a prod chain cannot close
either way.

What each hop checks (defence in depth):

  * **Delegation scoping.** The leaf must be accredited for (at least one of) the
    credential's types; the intersection becomes the *delegated scope*. Every
    accreditor above it must be accredited for a **superset** of that scope — a
    TAO cannot vouch for a type it was never authorised to accredit.
  * **Signature & identity.** The accreditation VC-JWT's ``iss`` equals the
    ``accreditedBy`` DID it names, its signature verifies against that
    accreditor's *resolved* key, and its subject is the DID being accredited: the
    JWT ``sub`` and the credential's ``credentialSubject.id``, each one that is sent,
    must be exactly that DID, and at least one must be sent. An accreditation that names
    nobody, or another DID, is refused however well it is signed, so a registry cannot
    replay a RootTAO's or a TAO's accreditation into another issuer's record.
  * **Revocation (optional).** With a ``resolve_status_list`` the accreditation's
    own ``credentialStatus`` is checked too — a revoked accreditation breaks the
    chain, not just a TIR ``revoked`` role.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openvc.did.base import DidResolutionError
from openvc.proof._verify_common import safe_repr
from openvc.proof.errors import ProofError
from openvc.proof.vc_jwt import VcJwtProofSuite, VerifiedCredential
from openvc.status import ResolveStatusList, check_credential_status

from ._message import bounded_text
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
        if not acc.credential_types:             # unrestricted (wildcard) — accept, matching
            return acc                           # the single-level policy in openvc_ebsi.verify
        authorised = set(acc.credential_types)
        if leaf:
            if authorised & needed:
                return acc
        elif needed <= authorised:
            return acc
    return None


def _check_subject_binding(verified: VerifiedCredential, *, subject: str) -> None:
    """The verified accreditation must name *subject*, the DID whose registry record it was
    read from, and no one else.

    Two places name the accredited party, the JWT ``sub`` and the credential's
    ``credentialSubject.id``. Each one that is **sent** must be exactly *subject* (``""``,
    ``null`` and a non-string are sent and wrong, never "absent"), at least one must be sent,
    and a sent ``credentialSubject`` must be an object (an array of subjects names no single
    accredited DID). Anything else is :class:`AccreditationInvalid`.

    Why this is checked here and not left to the proof suite: the suite refuses a ``sub``
    that is not a string and a ``sub`` that disagrees with a non-empty ``credentialSubject.id``,
    but it reports the token's subject as ``None`` when neither is sent and as ``""`` when
    ``sub`` is empty (an empty ``sub`` also skips its comparison with ``credentialSubject.id``),
    and the check that used to live in :func:`_verify_accreditation` ran only ``if
    verified.subject``. So a RootTAO- or TAO-signed accreditation that named nobody, or an
    empty ``sub`` over a ``credentialSubject.id`` of another DID, placed in any issuer's record
    by a registry (a bug, a steered response, a dishonest node: ADR-0009 D7) was accepted for
    that issuer, on every lane (#352, the review of PR #354)."""
    names: list[tuple[str, Any]] = []
    if "sub" in verified.claims:
        names.append(("sub", verified.claims["sub"]))
    credential = verified.credential
    if "credentialSubject" in credential:
        cs = credential["credentialSubject"]
        if not isinstance(cs, dict):
            raise AccreditationInvalid(
                f"accreditation for {safe_repr(subject)} has a credentialSubject that is not "
                f"an object: {safe_repr(cs)}")
        if "id" in cs:
            names.append(("credentialSubject.id", cs["id"]))
    if not names:
        raise AccreditationInvalid(
            f"accreditation for {safe_repr(subject)} names no subject (neither sub nor "
            "credentialSubject.id), so it cannot be bound to the accredited DID")
    for where, value in names:
        if not isinstance(value, str) or value != subject:
            raise AccreditationInvalid(
                f"accreditation subject ({where}) {safe_repr(value)} != "
                f"accredited DID {safe_repr(subject)}")


def _verify_accreditation(
    acc: Accreditation, *, subject: str, accreditor: str,
    resolver: DidEbsiResolver, proof_suite: VcJwtProofSuite,
) -> dict[str, Any]:
    """Verify the accreditation VC-JWT was signed by *accreditor* and issued for
    *subject*; return its verified credential (the ``vc`` object). Raises
    :class:`AccreditationInvalid` on any inconsistency, a token the suite cannot read
    included (its ``MalformedToken`` is an ``OpenvcError``, not an ``EbsiError``; here it
    is the ``__cause__``)."""
    if not acc.credential_jwt:
        raise AccreditationInvalid(
            f"no raw accreditation token for {subject!r}; cannot verify its proof")

    try:
        iss, kid = proof_suite.peek_issuer(acc.credential_jwt)
    except ProofError as exc:
        raise AccreditationInvalid(
            f"accreditation for {safe_repr(subject)} is not a readable token: "
            f"{bounded_text(exc)}") from exc
    if iss != accreditor:
        raise AccreditationInvalid(
            f"accreditation issuer {safe_repr(iss)} != accreditedBy {safe_repr(accreditor)}")

    try:
        doc = resolver.resolve(accreditor)
    except DidResolutionError as exc:
        raise AccreditationInvalid(
            f"cannot resolve accreditor {safe_repr(accreditor)}: {exc}") from exc
    vm = doc.key_by_kid(kid)
    if vm is None:
        raise AccreditationInvalid(
            f"no verification method {safe_repr(kid)} for accreditor {safe_repr(accreditor)}")

    try:
        verified = proof_suite.verify(acc.credential_jwt, public_key_jwk=vm.public_key_jwk)
    except ProofError as exc:
        raise AccreditationInvalid(
            f"accreditation for {subject!r} failed verification: {exc}") from exc

    _check_subject_binding(verified, subject=subject)
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
        except DidResolutionError as exc:
            # The walk subject is not a did:ebsi identifier (#266): the resolver refused
            # it before any request. The class stays the one a 404 gave before the check
            # existed, but the message says the fact: it is not a DID, not "not registered".
            # A record that is not about the DID (#267) is a MalformedRegistryResponse
            # and is deliberately NOT caught here: it is malformed input, not an
            # untrusted issuer.
            raise NoTrustedAnchor(
                f"{safe_repr(current)} is not a did:ebsi identifier") from exc

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
            # a wildcard leaf (no type restriction) delegates the credential's types;
            # otherwise the scope is what the leaf accreditation and the credential share
            scope = (set(credential_types) if not acc.credential_types
                     else set(acc.credential_types) & set(credential_types))
        hops.append(TrustHop(subject=current, accreditor=accreditor, accreditation=acc))

        if accreditor in anchors:                    # reached the trust root
            return TrustChain(subject=subject_did, anchor=accreditor,
                              hops=tuple(hops), scope=frozenset(scope or ()))
        if accreditor in seen:
            raise TrustChainError(f"accreditation cycle detected at {accreditor!r}")

        seen.add(accreditor)
        current = accreditor

    raise NoTrustedAnchor(
        f"no trusted anchor within {max_depth} hops from {safe_repr(subject_did)}")
