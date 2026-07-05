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

from .models import Accreditation, IssuerRecord
from .versioning import DidEbsiResolver


class EbsiVerificationError(Exception): ...
class VerificationMethodNotFound(EbsiVerificationError): ...
class IssuerNotTrusted(EbsiVerificationError): ...


@dataclass(frozen=True)
class VerifiedEbsiBadge:
    """The result of a successful (or trust-optional) EBSI verification."""
    credential: dict[str, Any]
    issuer: str
    subject: str | None
    trusted: bool                          # issuer holds a valid accreditation
    accreditation: Accreditation | None    # the one that granted trust, if any
    issuer_record: IssuerRecord | None
    verified: VerifiedCredential           # the raw proof-suite result


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
    audience: str | None = None,
) -> VerifiedEbsiBadge:
    """Verify an EBSI-issued VC-JWT badge end to end.

    ``expected_types`` (if given) are asserted to be present in the credential.
    Trust is always evaluated against the TIR; ``require_trust`` only controls
    whether an untrusted issuer raises :class:`IssuerNotTrusted` or is returned
    with ``trusted=False``.
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

    # 5) issuer trust in the TIR (uses the reconciled issuer, not the peeked one).
    record = resolver.issuer_record(verified.issuer)
    accreditation = evaluate_issuer_trust(record, _credential_types(verified.credential))
    trusted = accreditation is not None
    if require_trust and not trusted:
        raise IssuerNotTrusted(
            f"issuer {verified.issuer!r} has no valid accreditation for "
            f"types {_credential_types(verified.credential)}")

    return VerifiedEbsiBadge(
        credential=verified.credential,
        issuer=verified.issuer,
        subject=verified.subject,
        trusted=trusted,
        accreditation=accreditation,
        issuer_record=record,
        verified=verified,
    )
