"""
openvc.trustlist.consume — verify + walk an EU Trusted List hierarchy into a set
of X.509 trust anchors.

:func:`walk_lotl` starts at the **caller-pinned** LOTL signer certificate(s) (the
Commission keys — there is no implicit root, ADR-0003 D5), verifies the LOTL's XML
signature via an **injected** ``verify_signature`` callback (fail-closed — a list is
never trusted unverified), follows each pointer to a national TL, verifies *that*
TL against the signer certs the LOTL vouched for, and collects the selected trust
services' certificates. A TL that cannot be fetched, verified, or is expired
contributes **zero** anchors and is recorded in :attr:`TrustAnchorSet.problems` —
never silently trusted, never aborting the walk (ADR-0003 D6).

XML-signature verification is not in core (ETSI XAdES is heavy): pass a
``verify_signature`` — the ``[trustlist]`` extra ships a reference one, or inject
your own. Without it, consumption raises :class:`TrustListSignatureUnavailable`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from .errors import (
    TrustListError,
    TrustListParseError,
    TrustListSignatureError,
    TrustListSignatureUnavailable,
)
from .model import TrustAnchorSet, TrustList, TrustListProblem, TrustServiceAnchor
from .parse import DEFAULT_MAX_BYTES, parse_trust_list

# Verify a TL's enveloped XML signature over *xml* against the expected signer
# certificate(s); MUST raise on any failure and return None on success.
VerifySignature = Callable[[bytes, "Sequence[Any]"], None]
# Fetch a TL URL -> its raw bytes (pass an SSRF-guarded fetch).
FetchTrustList = Callable[[str], bytes]

_ETSI = "http://uri.etsi.org/TrstSvc"


class ServiceStatus:
    """ETSI TS 119 612 ``ServiceStatus`` URIs (the ones a verifier usually gates on)."""
    GRANTED = f"{_ETSI}/TrustedList/Svcstatus/granted"
    WITHDRAWN = f"{_ETSI}/TrustedList/Svcstatus/withdrawn"
    DEPRECATED_AT_NATIONAL_LEVEL = f"{_ETSI}/TrustedList/Svcstatus/deprecatedatnationallevel"


class ServiceType:
    """ETSI TS 119 612 ``ServiceTypeIdentifier`` URIs.

    A convenience set of the identifiers observed on the live EU Trusted Lists under
    **TLv6** (ETSI TS 119 612 v2.4.1, mandatory since 29 Apr 2026). These are just
    names — :class:`Select` matches ``ServiceTypeIdentifier`` verbatim, so **any** URI
    works, including the EUDI-wallet trust services (issuance of QEAA / EAA / PuB-EAA,
    qualified electronic ledgers) that v2.4.1 introduces but national lists have not
    widely populated yet: pass their URI to :class:`Select` as it rolls out.
    """
    CA_QC = f"{_ETSI}/Svctype/CA/QC"                 # CA issuing qualified certificates
    CA_PKC = f"{_ETSI}/Svctype/CA/PKC"              # CA issuing public-key certificates
    NATIONAL_ROOT_CA_QC = f"{_ETSI}/Svctype/NationalRootCA-QC"
    OCSP_QC = f"{_ETSI}/Svctype/Certstatus/OCSP/QC"
    OCSP = f"{_ETSI}/Svctype/Certstatus/OCSP"        # non-qualified OCSP
    CRL_QC = f"{_ETSI}/Svctype/Certstatus/CRL/QC"
    TSA_QTST = f"{_ETSI}/Svctype/TSA/QTST"           # qualified timestamping
    TSA = f"{_ETSI}/Svctype/TSA"                     # non-qualified timestamping
    # Other qualified eIDAS trust services carried on TLv6 national lists:
    EDS_Q = f"{_ETSI}/Svctype/EDS/Q"                 # qualified electronic delivery
    EDS_REM_Q = f"{_ETSI}/Svctype/EDS/REM/Q"         # qualified registered e-mail delivery
    PSES_Q = f"{_ETSI}/Svctype/PSES/Q"               # qualified preservation of e-signatures
    QES_VALIDATION_Q = f"{_ETSI}/Svctype/QESValidation/Q"          # qualified QES validation
    REMOTE_QSIGCD_MANAGEMENT_Q = f"{_ETSI}/Svctype/RemoteQSigCDManagement/Q"
    REMOTE_QSEALCD_MANAGEMENT_Q = f"{_ETSI}/Svctype/RemoteQSealCDManagement/Q"
    ARCHIVING = f"{_ETSI}/Svctype/Archiv"            # archiving


@dataclass(frozen=True)
class Select:
    """A filter over trust services. A ``None`` facet matches everything; a set
    restricts to its members. The default (see :data:`DEFAULT_SELECT`) keeps
    ``granted`` qualified-CA services — the ones that issue EUDI issuer certs."""
    service_types: frozenset[str] | None = None
    statuses: frozenset[str] | None = None
    territories: frozenset[str] | None = None

    def matches(self, anchor: TrustServiceAnchor) -> bool:
        if self.service_types is not None and anchor.service_type not in self.service_types:
            return False
        if self.statuses is not None and anchor.service_status not in self.statuses:
            return False
        if self.territories is not None and (anchor.territory or "") not in self.territories:
            return False
        return True


DEFAULT_SELECT = Select(
    service_types=frozenset({ServiceType.CA_QC}),
    statuses=frozenset({ServiceStatus.GRANTED}),
)


def default_trust_list_fetch(url: str) -> bytes:
    """The blessed SSRF-guarded TL fetch: :func:`openvc.fetch.https_bytes_fetch` with a
    TL-sized byte cap (national TLs run to a few MB)."""
    from ..fetch import https_bytes_fetch
    return https_bytes_fetch(url, max_bytes=DEFAULT_MAX_BYTES)


def consume_trust_list(
    xml: bytes, *,
    verify_signature: VerifySignature | None,
    expected_signer_certs: Sequence[Any],
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TrustList:
    """Verify a TL's XML signature (fail-closed) **then** parse it into a
    :class:`TrustList`.

    *verify_signature* is handed the raw bytes and *expected_signer_certs* and must
    raise on any failure; if it is ``None`` this raises
    :class:`TrustListSignatureUnavailable` — a list is never parsed-and-trusted
    unverified. Signature verification runs before parsing so an unauthentic list is
    rejected outright."""
    if verify_signature is None:
        raise TrustListSignatureUnavailable(
            "no verify_signature callback given; a trust list is never trusted "
            "unverified (pass openvc.trustlist.verify_xades_enveloped from the "
            "[trustlist] extra, or inject your own)")
    try:
        verify_signature(bytes(xml), tuple(expected_signer_certs))
    except TrustListError:
        raise
    except Exception as exc:                    # any raise from the callback = not authentic
        raise TrustListSignatureError(
            f"trust list signature verification failed: {exc}") from exc
    return parse_trust_list(xml, max_bytes=max_bytes)


def walk_lotl(
    lotl_url: str, *,
    lotl_signer_certs: Sequence[Any],
    verify_signature: VerifySignature | None,
    fetch: FetchTrustList = default_trust_list_fetch,
    select: Select | None = DEFAULT_SELECT,
    now: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TrustAnchorSet:
    """Walk the LOTL at *lotl_url* down to each national TL and return the selected
    X.509 trust anchors.

    Trust is rooted in *lotl_signer_certs* (the caller-pinned Commission keys). Each
    TL's XML signature is verified via *verify_signature* (fail-closed). *select*
    filters the trust services (default: ``granted`` qualified-CA — pass ``None`` for
    all); *fetch* performs the SSRF-guarded GETs. A TL that cannot be fetched /
    verified / is expired contributes no anchors and is recorded in the result's
    ``problems`` — never silently trusted (ADR-0003 D6). Pass *now* to pin the
    expiry evaluation instant."""
    instant = _utc(now) if now is not None else datetime.now(timezone.utc)
    problems: list[TrustListProblem] = []

    try:
        lotl_bytes = fetch(lotl_url)
    except Exception as exc:                    # LOTL unreachable -> no anchors at all
        return TrustAnchorSet(
            anchors=(), problems=(TrustListProblem(lotl_url, "fetch", str(exc)),))
    try:
        lotl = consume_trust_list(
            lotl_bytes, verify_signature=verify_signature,
            expected_signer_certs=lotl_signer_certs, max_bytes=max_bytes)
    except TrustListError as exc:
        return TrustAnchorSet(
            anchors=(), problems=(TrustListProblem(lotl_url, _stage(exc), str(exc)),))
    if _expired(lotl, instant):
        return TrustAnchorSet(anchors=(), problems=(
            TrustListProblem(lotl_url, "expired",
                             f"LOTL NextUpdate {lotl.next_update} is in the past"),))

    anchors: list[TrustServiceAnchor] = []
    for pointer in lotl.pointers:
        # a pointer to another LOTL (a pivot) yields no service anchors — skip it
        if pointer.tsl_type and pointer.tsl_type.endswith("EUlistofthelists"):
            continue
        if (select is not None and select.territories is not None
                and (pointer.territory or "") not in select.territories):
            continue
        try:
            tl_bytes = fetch(pointer.location)
        except Exception as exc:
            problems.append(TrustListProblem(pointer.location, "fetch", str(exc)))
            continue
        try:
            tl = consume_trust_list(
                tl_bytes, verify_signature=verify_signature,
                expected_signer_certs=pointer.signer_certs, max_bytes=max_bytes)
        except TrustListError as exc:
            problems.append(TrustListProblem(pointer.location, _stage(exc), str(exc)))
            continue
        if _expired(tl, instant):
            problems.append(TrustListProblem(
                pointer.location, "expired",
                f"NextUpdate {tl.next_update} is in the past"))
            continue
        for provider in tl.providers:
            for svc in provider.services:
                if select is None or select.matches(svc):
                    anchors.append(svc)

    return TrustAnchorSet(anchors=tuple(anchors), problems=tuple(problems))


def _stage(exc: TrustListError) -> str:
    if isinstance(exc, (TrustListSignatureError, TrustListSignatureUnavailable)):
        return "signature"
    if isinstance(exc, TrustListParseError):
        return "parse"
    return "consume"


def _expired(tl: TrustList, now: datetime) -> bool:
    return tl.next_update is not None and tl.next_update < now


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "DEFAULT_SELECT",
    "FetchTrustList",
    "Select",
    "ServiceStatus",
    "ServiceType",
    "VerifySignature",
    "consume_trust_list",
    "default_trust_list_fetch",
    "walk_lotl",
]
