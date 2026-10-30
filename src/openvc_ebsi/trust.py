"""
openvc_ebsi.trust — recursive EBSI trust-chain verification.

Walk an issuer up the accreditation chain (``TI -> TAO -> ... -> RootTAO``),
verifying at each hop that the accreditation is a real VC-JWT, with a live registry role,
signed
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

  * **Delegation scoping.** The leaf must be accredited for **every specific type** of
    the credential (the generic ``VerifiableCredential`` / ``VerifiableAttestation`` /
    ``VerifiableAccreditation`` say nothing about what may be issued and are ignored on
    both sides; #367); those specific types are the *delegated scope*. Every accreditor
    above it must be accredited for a **superset** of that scope — a TAO cannot vouch
    for a type it was never authorised to accredit. A credential that carries only
    generic types has nothing to be accredited for and is refused.
  * **Signature & identity.** The accreditation VC-JWT's ``iss`` equals the
    ``accreditedBy`` DID it names, its signature verifies against that
    accreditor's *resolved* key, and its subject is the DID being accredited: the
    JWT ``sub`` and the credential's ``credentialSubject.id``, each one that is sent,
    must be exactly that DID, and at least one must be sent. An accreditation that names
    nobody, or another DID, is refused however well it is signed, so a registry cannot
    replay a RootTAO's or a TAO's accreditation into *another* issuer's record.
  * **Kind and scope (#368).** An accreditation authorises only the types its
    ``accreditedFor`` lists: one that lists none (an onboarding authorisation, a plain
    attestation, a token with no ``accreditedFor`` or a misspelt member) authorises
    **nothing**, there is no unrestricted accreditation; and the token's ``vc.type`` must
    name the kind of the hop, ``VerifiableAccreditationToAttest`` at the leaf and
    ``VerifiableAccreditationToAccredit`` for the accreditation read from an accreditor's
    record above it (EBSI's own schema makes ``accreditedFor`` required; its trust model
    issues the two kinds). So a RootTAO- or TAO-signed credential for the *same* DID that is
    not an accreditation, placed in that DID's record, is set aside.
  * **Revocation (optional).** With a ``resolve_status_list`` the accreditation's
    own ``credentialStatus`` is checked too — a revoked accreditation breaks the
    chain, not just a TIR ``Revoked`` role. And the role itself is an exact allow-list
    (#358): only ``RootTAO``, ``TAO`` or ``TI`` is eligible, and above the leaf only
    ``RootTAO`` or ``TAO`` may accredit; ``Revoked`` (the spelling both registry APIs use),
    ``undefined``, an absent member and any other string are set aside, never read as live.
    The anchor's own record is not read: the caller pins the anchor DID, and the walk stops
    at it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openvc.did.base import DidResolutionError
from openvc.proof._verify_common import safe_repr
from openvc.proof.errors import ProofError
from openvc.proof.vc_jwt import VcJwtProofSuite, VerifiedCredential
from openvc.status import ResolveStatusList, StatusListError, check_credential_status

from ._message import bounded_text
from .errors import EbsiError
from .http import HttpNotFound
from .models import (
    ACCREDITATION_TO_ACCREDIT,
    ACCREDITATION_TO_ATTEST,
    Accreditation,
    IssuerRecord,
    specific_types,
)
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
    """An eligible accreditation authorising every type in *needed* (a non-empty set of
    SPECIFIC types: the credential's at the leaf, the delegated scope above it).

    Eligible is :func:`accreditation_ineligibility` answering ``None``: a live role (#358), a
    delegating one above the leaf, the kind of the hop in ``vc.type``, and an ``accreditedFor``
    that lists at least one specific type (#368, #367). Then the scope, the same rule at every
    position (#367, rule (b)): the specific types of ``accreditedFor`` must be a **superset**
    of *needed*. At the leaf that means the issuer is accredited for every specific type the
    credential carries (until 1.38.0 one shared type was enough, and on real EBSI data the
    shared type was always a generic one); above the leaf, that the accreditor can delegate
    everything beneath it. There is no unrestricted accreditation.
    """
    if not record.has_attributes or not needed:
        return None
    for acc in record.accreditations:
        if accreditation_ineligibility(acc, leaf=leaf) is not None:
            continue
        if needed <= acc.specific_credential_types:
            return acc
    return None


_ROLE_SHOWN_MAX = 48            # a real role is at most 9 characters; the rest is for a diagnosis


def _short_role(role: str) -> str:
    """A registry-supplied role for a message: ``safe_repr`` of at most ``_ROLE_SHOWN_MAX``
    characters, with the full length named when it was cut (a message that quotes a bounded
    type list and a DID beside it stays readable)."""
    if len(role) <= _ROLE_SHOWN_MAX:
        return safe_repr(role)
    return f"{safe_repr(role[:_ROLE_SHOWN_MAX])}... ({len(role)} chars)"


def accreditation_ineligibility(acc: Accreditation, *, leaf: bool) -> str | None:
    """Why *acc* cannot authorise anything at this position of a chain, or ``None`` when it
    can (its scope is then the next question). Shared by the recursive walk and the
    single-level policy (``openvc_ebsi.verify``), so the two never disagree. In order:

    1. the role (#358): ``issuerType`` must be a live role, and above the leaf a delegating
       one;
    2. the kind (#368): ``vc.type`` must name ``VerifiableAccreditationToAttest`` at the leaf,
       ``VerifiableAccreditationToAccredit`` above it;
    3. the scope (#368, #367): ``accreditedFor`` must list at least one type, and at least
       one SPECIFIC type (the generic base types authorise nothing). An accreditation
       authorises only what it lists; there is no unrestricted one.

    The text is bounded (``safe_repr`` / ``bounded_text`` on registry-supplied values)."""
    if not acc.has_trust_role:
        return (f"issuerType {_short_role(acc.issuer_type)} is not a live trust role "
                f"(RootTAO, TAO or TI)")
    if not leaf and not acc.can_accredit:
        return (f"issuerType {_short_role(acc.issuer_type)} is not a role that may accredit "
                f"(RootTAO or TAO)")
    wanted = ACCREDITATION_TO_ATTEST if leaf else ACCREDITATION_TO_ACCREDIT
    if wanted not in acc.accreditation_types:
        return f"vc.type {bounded_text(list(acc.accreditation_types))} does not name {wanted}"
    if not acc.credential_types:
        return "accreditedFor names no type (an accreditation authorises only what it lists)"
    if not acc.specific_credential_types:
        return ("accreditedFor names only generic types (VerifiableCredential, "
                "VerifiableAttestation, VerifiableAccreditation), which authorise nothing specific")
    return None


def ineligible_note(record: IssuerRecord, *, leaf: bool) -> str:
    """The reasons :func:`accreditation_ineligibility` set accreditations of *record* aside,
    as a bounded clause for a "has no valid accreditation" message; ``""`` when it set none
    aside. Distinct reasons in first-seen order, at most three shown, the rest counted. The
    leading words of the messages that take the clause are unchanged (#358, #368)."""
    reasons: list[str] = []
    seen: set[str] = set()                       # a set beside the list: v4 attributes are uncapped
    for acc in record.accreditations:
        why = accreditation_ineligibility(acc, leaf=leaf)
        if why is not None and why not in seen:
            seen.add(why)
            reasons.append(why)
    if not reasons:
        return ""
    shown = "; ".join(reasons[:3])
    if len(reasons) > 3:
        shown += f" and {len(reasons) - 3} more"
    return f"; set aside: {shown}"


def _check_subject_binding(verified: VerifiedCredential, *, subject: str) -> None:
    """The verified accreditation must name *subject*, the DID whose registry record it was
    read from, and no one else.

    Three spellings name the accredited party, the JWT ``sub`` and the credential's
    ``credentialSubject.id`` or ``credentialSubject.@id`` (what ``id`` aliases in JSON-LD, the
    spelling the suite's ``_reconcile`` honours for ``issuer``). Each one that is **sent** must
    be exactly *subject* (``""``, ``null`` and a non-string are sent and wrong, never
    "absent"), at least one must be sent, and a sent ``credentialSubject`` must be an object
    (an array of subjects names no single accredited DID). Anything else is
    :class:`AccreditationInvalid`.

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
        for key in ("id", "@id"):
            if key in cs:
                names.append((f"credentialSubject.{key}", cs[key]))
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
    wanted = specific_types(credential_types)
    if subject_did in anchors:                       # the leaf is itself an anchor
        return TrustChain(subject=subject_did, anchor=subject_did, hops=(), scope=wanted)
    if not wanted:
        # the generic base types say nothing about what an issuer may issue, so a credential
        # that carries only them has nothing to be accredited for (#367): refused before any
        # request, as single-level trust refuses it
        raise NoTrustedAnchor(
            f"the credential's types {bounded_text(list(credential_types))} name no specific "
            f"type (VerifiableCredential, VerifiableAttestation and VerifiableAccreditation are "
            f"generic): nothing to be accredited for")

    hops: list[TrustHop] = []
    current = subject_did
    seen = {current}
    scope: frozenset[str] | None = None              # delegated specific types, fixed at the leaf

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
        needed = wanted if is_leaf else scope
        assert needed is not None
        acc = _pick_accreditation(record, set(needed), leaf=is_leaf)
        if acc is None:
            raise NoTrustedAnchor(
                f"{current!r} has no valid accreditation for "
                + ("the credential's types" if is_leaf
                   else f"the delegated types {bounded_text(sorted(needed))}")
                + ineligible_note(record, leaf=is_leaf))

        accreditor = acc.tao
        if not accreditor:
            raise AccreditationInvalid(
                f"accreditation for {current!r} names no accreditor (accreditedBy)")

        vc = _verify_accreditation(acc, subject=current, accreditor=accreditor,
                                   resolver=resolver, proof_suite=proof_suite)
        if resolve_status_list is not None:
            try:
                status = check_credential_status(vc, resolve_status_list=resolve_status_list)
            except StatusListError as exc:
                # the accreditation's own `credentialStatus` (signed by the accreditor) is of a
                # shape the status module refuses: its revocation cannot be checked, so the hop
                # fails closed as a typed trust error, not as the status module's OpenvcError
                # escaping `verify_trust_chain` (the review of PR #365)
                raise AccreditationInvalid(
                    f"the accreditation for {safe_repr(current)} has a credentialStatus that "
                    f"cannot be checked: {bounded_text(exc)}") from exc
            if status.revoked:
                raise AccreditationRevoked(
                    f"the accreditation for {current!r} is revoked via its status list")

        if is_leaf:                                  # fix the delegated scope
            # the credential's specific types, every one of which the leaf accreditation lists
            # (the pick required that; #367), so what the accreditors above must cover
            scope = wanted
        hops.append(TrustHop(subject=current, accreditor=accreditor, accreditation=acc))

        if accreditor in anchors:                    # reached the trust root
            return TrustChain(subject=subject_did, anchor=accreditor,
                              hops=tuple(hops), scope=wanted)   # == scope, fixed at the leaf
        if accreditor in seen:
            raise TrustChainError(f"accreditation cycle detected at {accreditor!r}")

        seen.add(accreditor)
        current = accreditor

    raise NoTrustedAnchor(
        f"no trusted anchor within {max_depth} hops from {safe_repr(subject_did)}")
