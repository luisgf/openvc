"""
openvc.trustlist.lote — consume ETSI TS 119 602 **Lists of Trusted Entities**
(LoTE, the JSON trusted-list binding) as a verifier X.509 trust-anchor source.

TS 119 602 V1.1.1 is the format-agnostic successor data model to the TS 119 612
XML Trusted Lists (its Table A.1 maps the two field-by-field), and its EU
profiles are the anchor sources for the EUDI wallet ecosystem: Annex F is the
**WRPAC providers list** (who may issue relying-party access certificates) and
Annex G the **WRPRC providers list** (who may issue relying-party registration
certificates — the registrar anchors
:func:`openvc.rp_registration.verify_rp_registration_certificate` consumes).
One interface, two encodings: a parsed LoTE lands in the same
:class:`~openvc.trustlist.model.TrustList` / :class:`~openvc.trustlist.model.TrustAnchorSet`
shapes the 119 612 lane produces, so ``.certificates`` feeds the existing X.509
path unchanged.

A JSON LoTE is distributed as a **compact JAdES baseline-B signature whose
payload is the list** (clause 6.8 + Annexes D.4–I.4: "compact JAdES Baseline B
… as specified in ETSI TS 119 182-1"), so verification runs on the library's
JOSE primitives: the ``{ES256, ES384, EdDSA, Ed25519}`` allow-list is applied
**before** any crypto, ``crit`` is allow-listed exactly like the WRPRC lane
(:mod:`openvc.rp_registration`), the signer comes from ``x5c`` and must
authenticate against **caller-pinned** certificates (no implicit root — the
same discipline as :func:`openvc.trustlist.walk_lotl`), and clause 6.8's DN
binding is enforced: the signing certificate's ``organizationName`` must match
a ``SchemeOperatorName`` value and its ``countryName`` the ``SchemeTerritory``.

Parsing is **strict and fail-closed on every field that feeds a trust
decision**: unknown structural members are rejected (the official JSON schema
is ``additionalProperties: false`` throughout), a ``bool`` is never accepted
where an ``int`` is required, date-times must be the UTC ``Z`` form clause
6.1.3 mandates, and an unrecognised **critical** scheme/service extension
rejects the list (clause 6.3.17). Purely informational sub-structures
(addresses, policy notices) are container-type-checked and otherwise carried
opaquely. A certificate blob that does not load is skipped, never silently
trusted (the :mod:`openvc.trustlist.parse` convention).

Two spec warts, handled deliberately:

* Table G.1 / clause C.2.2 spell the WRPRC status-determination URI
  ``…/WRPRCrovidersList/StatusDetn/EU`` (sic — the "P" of "Providers" is
  missing) and the EUDI reference implementation carries the typo verbatim, so
  :data:`EU_WRPRC_PROVIDERS_PROFILE` accepts **both** the literal and the
  corrected spelling — scheme metadata, not an authorization grant, so the
  tolerance cannot widen any privilege.
* The official JSON schema nests an ``additionalProperties: false`` *inside*
  ``ServiceDigitalIdentity``'s ``properties`` (declaring a never-valid literal
  property of that name); this parser is the authority instead, with the five
  schema-defined members allowed.
"""
from __future__ import annotations

import base64
import calendar
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from .consume import Select
from .errors import (
    TrustListError,
    TrustListParseError,
    TrustListProfileError,
    TrustListSignatureError,
)
from .model import (
    TrustAnchorSet,
    TrustList,
    TrustListProblem,
    TrustServiceAnchor,
    TrustServiceProvider,
    TslPointer,
)
from .parse import DEFAULT_MAX_BYTES

# Fetch a LoTE URL -> its raw bytes (pass an SSRF-guarded fetch).
FetchLote = Callable[[str], bytes]

_URI_19602 = "http://uri.etsi.org/19602"

# JAdES header parameters this verifier processes — the same set as the WRPRC
# lane (openvc.rp_registration): a V1.1.1-era JAdES producer listed its
# non-registered parameters in ``crit``, so the check allow-lists exactly what
# is understood and fails closed on the rest.
_KNOWN_CRIT = frozenset({"alg", "typ", "x5c", "iat"})


class LoteType:
    """The EU ``LoTEType`` URIs of TS 119 602 clause C.2.1."""
    EU_PID_PROVIDERS = f"{_URI_19602}/LoTEType/EUPIDProvidersList"
    EU_WALLET_PROVIDERS = f"{_URI_19602}/LoTEType/EUWalletProvidersList"
    EU_WRPAC_PROVIDERS = f"{_URI_19602}/LoTEType/EUWRPACProvidersList"
    EU_WRPRC_PROVIDERS = f"{_URI_19602}/LoTEType/EUWRPRCProvidersList"
    EU_PUB_EAA_PROVIDERS = f"{_URI_19602}/LoTEType/EUPubEAAProvidersList"
    EU_REGISTRARS_AND_REGISTERS = f"{_URI_19602}/LoTEType/EURegistrarsAndRegistersList"


class LoteServiceType:
    """The ``ServiceTypeIdentifier`` URIs of the WRPAC / WRPRC providers-list
    profiles (TS 119 602 Tables F.3 / G.3) — each profile uses its pair "to the
    exclusion of any other"."""
    WRPAC_ISSUANCE = f"{_URI_19602}/SvcType/WRPAC/Issuance"
    WRPAC_REVOCATION = f"{_URI_19602}/SvcType/WRPAC/Revocation"
    WRPRC_ISSUANCE = f"{_URI_19602}/SvcType/WRPRC/Issuance"
    WRPRC_REVOCATION = f"{_URI_19602}/SvcType/WRPRC/Revocation"


@dataclass(frozen=True)
class LoteProfile:
    """A LoTE profile (TS 119 602 clause 4.7): scheme-defined constraints a
    specific list must satisfy on top of the general data model. Checking a list
    against a profile is a conformance gate — every mismatch fails closed as
    :class:`~openvc.trustlist.errors.TrustListProfileError`."""
    name: str
    lote_type: str                          # required LoTEType (Table x.1)
    status_determination: tuple[str, ...]   # accepted StatusDeterminationApproach spellings
    scheme_rules: str                       # required SchemeTypeCommunityRules URI
    territory: str                          # required SchemeTerritory
    service_types: frozenset[str]           # the exclusive ServiceTypeIdentifier set
    max_update_months: int = 6              # NextUpdate - ListIssueDateTime ceiling


EU_WRPAC_PROVIDERS_PROFILE = LoteProfile(
    name="EU WRPAC providers list (TS 119 602 Annex F)",
    lote_type=LoteType.EU_WRPAC_PROVIDERS,
    status_determination=(f"{_URI_19602}/WRPACProvidersList/StatusDetn/EU",),
    scheme_rules=f"{_URI_19602}/WRPACProvidersList/schemerules/EU",
    territory="EU",
    service_types=frozenset(
        {LoteServiceType.WRPAC_ISSUANCE, LoteServiceType.WRPAC_REVOCATION}),
)

EU_WRPRC_PROVIDERS_PROFILE = LoteProfile(
    name="EU WRPRC providers list (TS 119 602 Annex G)",
    lote_type=LoteType.EU_WRPRC_PROVIDERS,
    status_determination=(
        # The literal Table G.1 / C.2.2 value — "WRPRCroviders" is a spec typo
        # the EUDI reference implementation reproduces verbatim…
        f"{_URI_19602}/WRPRCrovidersList/StatusDetn/EU",
        # …and the corrected spelling, so a future erratum keeps verifying.
        f"{_URI_19602}/WRPRCProvidersList/StatusDetn/EU",
    ),
    scheme_rules=f"{_URI_19602}/WRPRCProvidersList/schemerules/EU",
    territory="EU",
    service_types=frozenset(
        {LoteServiceType.WRPRC_ISSUANCE, LoteServiceType.WRPRC_REVOCATION}),
)


def default_lote_fetch(url: str) -> bytes:
    """The blessed SSRF-guarded LoTE fetch: :func:`openvc.fetch.https_bytes_fetch`
    with the trust-list byte cap."""
    from ..fetch import https_bytes_fetch
    return https_bytes_fetch(url, max_bytes=DEFAULT_MAX_BYTES)


# --------------------------------------------------------------------------- #
# strict structural parsing (runs on attacker-influenced bytes)
# --------------------------------------------------------------------------- #

def _require_mapping(value: Any, ctx: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TrustListParseError(f"{ctx} must be a JSON object")
    return value


def _require_list(value: Any, ctx: str) -> list[Any]:
    if not isinstance(value, list):
        raise TrustListParseError(f"{ctx} must be a JSON array")
    return value


def _require_str(value: Any, ctx: str) -> str:
    if not isinstance(value, str):
        raise TrustListParseError(f"{ctx} must be a string")
    return value


def _require_int(value: Any, ctx: str) -> int:
    # bool is an int subclass — `true` is never a sequence number.
    if not isinstance(value, int) or isinstance(value, bool):
        raise TrustListParseError(f"{ctx} must be an integer")
    return value


def _check_keys(
    obj: Mapping[str, Any], *, allowed: frozenset[str], required: frozenset[str], ctx: str,
) -> None:
    """Enforce the official schema's ``additionalProperties: false`` + required
    members — an unknown structural member could carry semantics this verifier
    does not understand, so it rejects rather than ignores."""
    unknown = [k for k in obj if k not in allowed]
    if unknown:
        raise TrustListParseError(f"{ctx} carries unknown member(s) {sorted(unknown)!r}")
    missing = [k for k in required if k not in obj]
    if missing:
        raise TrustListParseError(f"{ctx} is missing required member(s) {sorted(missing)!r}")


def _ml_strings(value: Any, ctx: str) -> list[str]:
    """A non-empty multilingual character-string sequence → its values, English
    first (clause 6.1.4)."""
    items = _require_list(value, ctx)
    if not items:
        raise TrustListParseError(f"{ctx} must not be empty")
    english: list[str] = []
    other: list[str] = []
    for i, item in enumerate(items):
        entry = _require_mapping(item, f"{ctx}[{i}]")
        _check_keys(entry, allowed=frozenset({"lang", "value"}),
                    required=frozenset({"lang", "value"}), ctx=f"{ctx}[{i}]")
        lang = _require_str(entry["lang"], f"{ctx}[{i}].lang")
        text = _require_str(entry["value"], f"{ctx}[{i}].value")
        (english if lang.lower() == "en" else other).append(text)
    return english + other


def _ml_uris(value: Any, ctx: str) -> list[str]:
    """A non-empty multilingual-pointer sequence → its ``uriValue`` strings."""
    items = _require_list(value, ctx)
    if not items:
        raise TrustListParseError(f"{ctx} must not be empty")
    uris: list[str] = []
    for i, item in enumerate(items):
        entry = _require_mapping(item, f"{ctx}[{i}]")
        _check_keys(entry, allowed=frozenset({"lang", "uriValue"}),
                    required=frozenset({"lang", "uriValue"}), ctx=f"{ctx}[{i}]")
        _require_str(entry["lang"], f"{ctx}[{i}].lang")
        uris.append(_require_str(entry["uriValue"], f"{ctx}[{i}].uriValue"))
    return uris


def _datetime_z(value: Any, ctx: str) -> datetime:
    """Clause 6.1.3: ISO 8601, UTC, second precision, the literal ``Z``
    designator."""
    text = _require_str(value, ctx)
    if not text.endswith("Z"):
        raise TrustListParseError(f"{ctx} must be a UTC date-time ending in 'Z' (clause 6.1.3)")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise TrustListParseError(f"{ctx} is not a valid date-time: {text!r}") from exc
    return parsed


def _reject_critical_extensions(value: Any, ctx: str) -> None:
    """Clause 6.3.17 / 6.6.9: extension formats are left open, but a critical
    extension this verifier does not recognise **shall** reject the list. The
    open format means criticality can only be detected best-effort — any member
    whose common criticality spellings are ``true`` rejects; everything else is
    carried opaquely."""
    items = _require_list(value, ctx)
    if not items:
        raise TrustListParseError(f"{ctx} must not be empty")
    for i, item in enumerate(items):
        if isinstance(item, Mapping) and any(
                item.get(k) is True for k in ("critical", "Critical")):
            raise TrustListParseError(
                f"{ctx}[{i}] is a critical extension this verifier does not recognise "
                f"(clause 6.3.17: a LoTE with an unrecognised critical extension is rejected)")


_PKIOB_KEYS = frozenset({"encoding", "specRef", "val"})


def _certs_from_sdi(value: Any, ctx: str) -> list[Any]:
    """One ``ServiceDigitalIdentity`` → its loaded ``X509Certificates``. A blob
    that does not parse as DER is skipped (a malformed certificate never becomes
    a silent anchor); structural violations reject."""
    sdi = _require_mapping(value, ctx)
    _check_keys(
        sdi,
        allowed=frozenset(
            {"X509Certificates", "X509SubjectNames", "PublicKeyValues", "X509SKIs", "OtherIds"}),
        required=frozenset(), ctx=ctx)
    from cryptography import x509
    certs: list[Any] = []
    if "X509Certificates" in sdi:
        entries = _require_list(sdi["X509Certificates"], f"{ctx}.X509Certificates")
        if not entries:
            raise TrustListParseError(f"{ctx}.X509Certificates must not be empty")
        for i, entry in enumerate(entries):
            ob = _require_mapping(entry, f"{ctx}.X509Certificates[{i}]")
            _check_keys(ob, allowed=_PKIOB_KEYS, required=frozenset({"val"}),
                        ctx=f"{ctx}.X509Certificates[{i}]")
            val = _require_str(ob["val"], f"{ctx}.X509Certificates[{i}].val")
            try:
                certs.append(x509.load_der_x509_certificate(base64.b64decode(val, validate=True)))
            except Exception:               # a malformed cert is dropped, not trusted
                continue
    return certs


_QUALIFIER_KEYS = frozenset(
    {"LoTEType", "SchemeOperatorName", "SchemeTypeCommunityRules", "SchemeTerritory", "MimeType"})


def _parse_pointer(value: Any, ctx: str) -> TslPointer:
    ptr = _require_mapping(value, ctx)
    _pointer_keys = frozenset({"LoTELocation", "ServiceDigitalIdentities", "LoTEQualifiers"})
    _check_keys(ptr, allowed=_pointer_keys, required=_pointer_keys, ctx=ctx)
    location = _require_str(ptr["LoTELocation"], f"{ctx}.LoTELocation")
    sdis = _require_list(ptr["ServiceDigitalIdentities"], f"{ctx}.ServiceDigitalIdentities")
    if not sdis:
        raise TrustListParseError(f"{ctx}.ServiceDigitalIdentities must not be empty")
    certs: list[Any] = []
    for i, sdi in enumerate(sdis):
        certs.extend(_certs_from_sdi(sdi, f"{ctx}.ServiceDigitalIdentities[{i}]"))
    qualifiers = _require_list(ptr["LoTEQualifiers"], f"{ctx}.LoTEQualifiers")
    if not qualifiers:
        raise TrustListParseError(f"{ctx}.LoTEQualifiers must not be empty")
    territory = None
    lote_type = None
    mime_type = None
    for i, q in enumerate(qualifiers):
        qual = _require_mapping(q, f"{ctx}.LoTEQualifiers[{i}]")
        _check_keys(qual, allowed=_QUALIFIER_KEYS,
                    required=frozenset({"LoTEType", "SchemeOperatorName", "MimeType"}),
                    ctx=f"{ctx}.LoTEQualifiers[{i}]")
        if lote_type is None:
            lote_type = _require_str(qual["LoTEType"], f"{ctx}.LoTEQualifiers[{i}].LoTEType")
        if mime_type is None:
            mime_type = _require_str(qual["MimeType"], f"{ctx}.LoTEQualifiers[{i}].MimeType")
        if territory is None and "SchemeTerritory" in qual:
            territory = _require_str(
                qual["SchemeTerritory"], f"{ctx}.LoTEQualifiers[{i}].SchemeTerritory")
    return TslPointer(
        location=location, signer_certs=tuple(certs),
        territory=territory, tsl_type=lote_type, mime_type=mime_type)


_SCHEME_KEYS = frozenset({
    "LoTEVersionIdentifier", "LoTESequenceNumber", "LoTEType", "SchemeOperatorName",
    "SchemeOperatorAddress", "SchemeName", "SchemeInformationURI", "StatusDeterminationApproach",
    "SchemeTypeCommunityRules", "SchemeTerritory", "PolicyOrLegalNotice",
    "HistoricalInformationPeriod", "PointersToOtherLoTE", "ListIssueDateTime", "NextUpdate",
    "DistributionPoints", "SchemeExtensions",
})
_SCHEME_REQUIRED = frozenset({
    "LoTEVersionIdentifier", "LoTESequenceNumber", "SchemeOperatorName",
    "ListIssueDateTime", "NextUpdate",
})
_SERVICE_INFO_KEYS = frozenset({
    "ServiceName", "ServiceDigitalIdentity", "ServiceTypeIdentifier", "ServiceStatus",
    "StatusStartingTime", "SchemeServiceDefinitionURI", "ServiceSupplyPoints",
    "ServiceDefinitionURI", "ServiceInformationExtensions",
})
_TE_INFO_KEYS = frozenset({
    "TEName", "TETradeName", "TEAddress", "TEInformationURI", "TEInformationExtensions",
})


def parse_lote(
    payload: Mapping[str, Any] | bytes, *, max_bytes: int = DEFAULT_MAX_BYTES,
) -> TrustList:
    """Parse a TS 119 602 JSON LoTE document into a :class:`TrustList` —
    strictly, fail-closed, WITHOUT any signature verification (use
    :func:`consume_lote`, which verifies first).

    Accepts the decoded top-level object (``{"LoTE": …}``) or raw JSON bytes.
    Raises :class:`TrustListParseError` on any structural violation."""
    if isinstance(payload, (bytes, bytearray)):
        if len(payload) > max_bytes:
            raise TrustListParseError(
                f"LoTE is {len(payload)} bytes, over the {max_bytes}-byte cap")
        try:
            decoded = json.loads(payload)
        except (ValueError, RecursionError) as exc:
            raise TrustListParseError(f"LoTE is not valid JSON: {exc}") from exc
    else:
        decoded = payload
    root = _require_mapping(decoded, "LoTE document")
    _check_keys(root, allowed=frozenset({"LoTE"}), required=frozenset({"LoTE"}),
                ctx="LoTE document")
    lote = _require_mapping(root["LoTE"], "LoTE")
    _check_keys(lote, allowed=frozenset({"ListAndSchemeInformation", "TrustedEntitiesList"}),
                required=frozenset({"ListAndSchemeInformation"}), ctx="LoTE")

    scheme = _require_mapping(lote["ListAndSchemeInformation"], "ListAndSchemeInformation")
    _check_keys(scheme, allowed=_SCHEME_KEYS, required=_SCHEME_REQUIRED,
                ctx="ListAndSchemeInformation")

    version = _require_int(scheme["LoTEVersionIdentifier"], "LoTEVersionIdentifier")
    sequence = _require_int(scheme["LoTESequenceNumber"], "LoTESequenceNumber")
    operator_names = _ml_strings(scheme["SchemeOperatorName"], "SchemeOperatorName")
    lote_type = (_require_str(scheme["LoTEType"], "LoTEType")
                 if "LoTEType" in scheme else None)
    territory = (_require_str(scheme["SchemeTerritory"], "SchemeTerritory")
                 if "SchemeTerritory" in scheme else None)
    if "HistoricalInformationPeriod" in scheme:
        _require_int(scheme["HistoricalInformationPeriod"], "HistoricalInformationPeriod")
    if "StatusDeterminationApproach" in scheme:
        _require_str(scheme["StatusDeterminationApproach"], "StatusDeterminationApproach")
    if "SchemeTypeCommunityRules" in scheme:
        _ml_uris(scheme["SchemeTypeCommunityRules"], "SchemeTypeCommunityRules")
    if "SchemeName" in scheme:
        _ml_strings(scheme["SchemeName"], "SchemeName")
    if "SchemeInformationURI" in scheme:
        _ml_uris(scheme["SchemeInformationURI"], "SchemeInformationURI")
    if "SchemeOperatorAddress" in scheme:
        _require_mapping(scheme["SchemeOperatorAddress"], "SchemeOperatorAddress")
    if "PolicyOrLegalNotice" in scheme:
        _require_list(scheme["PolicyOrLegalNotice"], "PolicyOrLegalNotice")
    if "DistributionPoints" in scheme:
        points = _require_list(scheme["DistributionPoints"], "DistributionPoints")
        if not points:
            raise TrustListParseError("DistributionPoints must not be empty")
        for i, p in enumerate(points):
            _require_str(p, f"DistributionPoints[{i}]")
    if "SchemeExtensions" in scheme:
        _reject_critical_extensions(scheme["SchemeExtensions"], "SchemeExtensions")

    issue = _datetime_z(scheme["ListIssueDateTime"], "ListIssueDateTime")
    # Clause 6.3.15: NextUpdate is null for a **closed** LoTE (scheme ceased);
    # a closed list contributes no anchors — the walk stages it as expired.
    next_update = (None if scheme["NextUpdate"] is None
                   else _datetime_z(scheme["NextUpdate"], "NextUpdate"))

    pointers: list[TslPointer] = []
    if "PointersToOtherLoTE" in scheme:
        raw_ptrs = _require_list(scheme["PointersToOtherLoTE"], "PointersToOtherLoTE")
        if not raw_ptrs:
            raise TrustListParseError("PointersToOtherLoTE must not be empty")
        for i, p in enumerate(raw_ptrs):
            pointers.append(_parse_pointer(p, f"PointersToOtherLoTE[{i}]"))

    providers: list[TrustServiceProvider] = []
    if "TrustedEntitiesList" in lote:
        entities = _require_list(lote["TrustedEntitiesList"], "TrustedEntitiesList")
        if not entities:
            raise TrustListParseError("TrustedEntitiesList must not be empty")
        for i, e in enumerate(entities):
            providers.append(_parse_entity(e, f"TrustedEntitiesList[{i}]", territory))

    return TrustList(
        tsl_type=lote_type, scheme_operator=operator_names[0], territory=territory,
        sequence_number=sequence, issue_datetime=issue.isoformat(), next_update=next_update,
        pointers=tuple(pointers), providers=tuple(providers), version=version)


def _parse_entity(value: Any, ctx: str, territory: str | None) -> TrustServiceProvider:
    entity = _require_mapping(value, ctx)
    _check_keys(entity, allowed=frozenset({"TrustedEntityInformation", "TrustedEntityServices"}),
                required=frozenset({"TrustedEntityInformation", "TrustedEntityServices"}), ctx=ctx)
    info = _require_mapping(entity["TrustedEntityInformation"], f"{ctx}.TrustedEntityInformation")
    _check_keys(info, allowed=_TE_INFO_KEYS,
                required=frozenset({"TEName", "TEAddress", "TEInformationURI"}),
                ctx=f"{ctx}.TrustedEntityInformation")
    names = _ml_strings(info["TEName"], f"{ctx}.TrustedEntityInformation.TEName")
    _require_mapping(info["TEAddress"], f"{ctx}.TrustedEntityInformation.TEAddress")
    _ml_uris(info["TEInformationURI"], f"{ctx}.TrustedEntityInformation.TEInformationURI")
    if "TEInformationExtensions" in info:
        _reject_critical_extensions(
            info["TEInformationExtensions"],
            f"{ctx}.TrustedEntityInformation.TEInformationExtensions")

    services: list[TrustServiceAnchor] = []
    raw_services = _require_list(entity["TrustedEntityServices"], f"{ctx}.TrustedEntityServices")
    if not raw_services:
        raise TrustListParseError(f"{ctx}.TrustedEntityServices must not be empty")
    for i, s in enumerate(raw_services):
        services.extend(_parse_service(s, f"{ctx}.TrustedEntityServices[{i}]", names[0], territory))
    return TrustServiceProvider(name=names[0], services=tuple(services))


def _parse_service(
    value: Any, ctx: str, te_name: str, territory: str | None,
) -> list[TrustServiceAnchor]:
    svc = _require_mapping(value, ctx)
    _check_keys(svc, allowed=frozenset({"ServiceInformation", "ServiceHistory"}),
                required=frozenset({"ServiceInformation"}), ctx=ctx)
    info = _require_mapping(svc["ServiceInformation"], f"{ctx}.ServiceInformation")
    _check_keys(info, allowed=_SERVICE_INFO_KEYS,
                required=frozenset({"ServiceName", "ServiceDigitalIdentity"}),
                ctx=f"{ctx}.ServiceInformation")
    names = _ml_strings(info["ServiceName"], f"{ctx}.ServiceInformation.ServiceName")
    service_type = ""
    if "ServiceTypeIdentifier" in info:
        service_type = _require_str(
            info["ServiceTypeIdentifier"], f"{ctx}.ServiceInformation.ServiceTypeIdentifier")
    service_status = ""
    if "ServiceStatus" in info:
        service_status = _require_str(
            info["ServiceStatus"], f"{ctx}.ServiceInformation.ServiceStatus")
    if "StatusStartingTime" in info:
        _datetime_z(info["StatusStartingTime"], f"{ctx}.ServiceInformation.StatusStartingTime")
    if "ServiceInformationExtensions" in info:
        _reject_critical_extensions(
            info["ServiceInformationExtensions"],
            f"{ctx}.ServiceInformation.ServiceInformationExtensions")
    certs = _certs_from_sdi(
        info["ServiceDigitalIdentity"], f"{ctx}.ServiceInformation.ServiceDigitalIdentity")
    return [
        TrustServiceAnchor(
            certificate=cert, service_type=service_type, service_status=service_status,
            tsp_name=te_name, service_name=names[0], territory=territory)
        for cert in certs
    ]


# --------------------------------------------------------------------------- #
# signed consumption (JAdES B-B compact, clause 6.8)
# --------------------------------------------------------------------------- #

def consume_lote(
    token: str | bytes, *,
    expected_signer_certs: Sequence[Any],
    profile: LoteProfile | None = None,
    now: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TrustList:
    """Verify a signed LoTE (compact JAdES baseline B) **then** parse it.

    In order: the compact-JWS envelope (the ``{ES256, ES384, EdDSA, Ed25519}``
    allow-list applied before any crypto; a fail-closed allow-listed ``crit``;
    ``x5c`` required); the signer authenticated against *expected_signer_certs*
    — the leaf matching a pinned certificate byte-for-byte (within that
    certificate's own validity window), or path-validating to the pinned set as
    anchors; the **signature** against the leaf key; the strict payload parse;
    clause 6.8's DN binding (signing-certificate ``organizationName`` must be a
    ``SchemeOperatorName`` value, ``countryName`` the ``SchemeTerritory`` when
    the list carries one); and, when *profile* is given, the profile's
    conformance gate (:class:`TrustListProfileError` on any mismatch).

    There is no implicit trust root: *expected_signer_certs* are
    ``cryptography`` ``x509.Certificate`` objects the caller pins (or, on a
    pointer walk, the certificates the pointing list vouched for)."""
    if isinstance(token, (bytes, bytearray)):
        try:
            token = bytes(token).decode("ascii")
        except UnicodeDecodeError as exc:
            raise TrustListParseError("a compact JAdES LoTE must be ASCII") from exc
    if not isinstance(token, str):
        raise TrustListParseError("LoTE token must be a compact-JWS string or bytes")
    if len(token) > max_bytes:
        raise TrustListParseError(
            f"LoTE token is {len(token)} bytes, over the {max_bytes}-byte cap")

    from ..proof._jws import parse_compact
    from ..proof.errors import ProofError
    from ..proof.vc_jwt import ALLOWED_ALGS

    try:
        header, payload, signing_input, signature = parse_compact(token)
    except ProofError as exc:
        raise TrustListParseError(f"LoTE is not a valid compact JWS: {exc}") from exc

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGS:
        raise TrustListSignatureError(
            f"LoTE alg {alg!r} is not permitted (need one of {sorted(ALLOWED_ALGS)})")
    _reject_unknown_crit(header)

    leaf, chain = _signer_chain(header)
    _authenticate_signer(leaf, chain, expected_signer_certs, now=now)

    from ..keys import KeyBackendError, verify_signature
    from ..x5c import X5cError, leaf_public_jwk
    try:
        public_jwk = leaf_public_jwk(leaf)
    except X5cError as exc:
        raise TrustListSignatureError(f"LoTE signing certificate: {exc}") from exc
    try:
        ok = verify_signature(alg=alg, public_jwk=public_jwk,
                              signing_input=signing_input, signature=signature)
    except KeyBackendError as exc:
        raise TrustListSignatureError(f"LoTE signature could not be checked: {exc}") from exc
    if not ok:
        raise TrustListSignatureError("LoTE signature verification failed")

    trust_list = parse_lote(payload, max_bytes=max_bytes)
    lote_obj = payload["LoTE"]
    _check_signer_dn(leaf, lote_obj["ListAndSchemeInformation"], territory=trust_list.territory)
    if profile is not None:
        _check_profile(trust_list, lote_obj, profile)
    return trust_list


def _reject_unknown_crit(header: Mapping[str, Any]) -> None:
    """RFC 7515 §4.1.11, with the WRPRC lane's allow-list stance: this verifier
    processes the JAdES parameters in :data:`_KNOWN_CRIT` and fails closed on
    anything else named critical."""
    if "crit" not in header:
        return
    crit = header["crit"]
    if not isinstance(crit, list) or not crit or not all(isinstance(c, str) for c in crit):
        raise TrustListSignatureError("LoTE 'crit' must be a non-empty array of strings")
    unknown = [c for c in crit if c not in _KNOWN_CRIT]
    if unknown:
        raise TrustListSignatureError(
            f"LoTE marks header parameter(s) {unknown!r} critical, which this verifier "
            f"does not process (understood: {sorted(_KNOWN_CRIT)})")
    missing = [c for c in crit if c not in header]
    if missing:
        raise TrustListSignatureError(
            f"LoTE 'crit' names header parameter(s) {missing!r} that are not present")


def _signer_chain(header: Mapping[str, Any]) -> tuple[Any, list[Any]]:
    from ..x5c import X5cError, load_x5c_chain

    x5c = header.get("x5c")
    if x5c is None:
        raise TrustListSignatureError(
            "LoTE JWS header has no 'x5c' chain to identify the scheme operator "
            "(TS 119 182-1 clause 5.1.7 requires a signing-certificate reference)")
    try:
        chain = load_x5c_chain(x5c)
    except X5cError as exc:
        raise TrustListSignatureError(f"LoTE 'x5c': {exc}") from exc
    return chain[0], chain


def _authenticate_signer(
    leaf: Any, chain: list[Any], expected: Sequence[Any], *, now: datetime | None,
) -> None:
    """Authenticate the ``x5c`` leaf against the caller-pinned certificates:
    byte-for-byte equality with a pinned certificate (checked inside its own
    validity window), or a path validation treating the pinned set as anchors —
    covering both the pointer model (the voucher pins the actual signer) and a
    CA pin. No pin, no trust."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from ..x5c import X5cError, validate_cert_chain

    pinned = [c for c in expected if isinstance(c, x509.Certificate)]
    if not pinned:
        raise TrustListSignatureError(
            "no expected signer certificates given (a sequence of x509.Certificate "
            "objects) — a LoTE is never trusted unverified")
    leaf_der = leaf.public_bytes(Encoding.DER)
    if any(leaf_der == c.public_bytes(Encoding.DER) for c in pinned):
        instant = now if now is not None else datetime.now(timezone.utc)
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        if not (leaf.not_valid_before_utc <= instant <= leaf.not_valid_after_utc):
            raise TrustListSignatureError(
                "LoTE signing certificate matches a pinned certificate but is outside "
                "its own validity window")
        return
    try:
        validate_cert_chain(leaf, chain[1:], trust_anchors=pinned, now=now)
    except X5cError as exc:
        raise TrustListSignatureError(
            f"LoTE signing certificate is not pinned and did not validate to the "
            f"pinned set: {exc}") from exc


def _check_signer_dn(leaf: Any, scheme: Mapping[str, Any], *, territory: str | None) -> None:
    """Clause 6.8: the signing certificate's subject ``countryName`` shall match
    ``SchemeTerritory`` and its ``organizationName`` one of the
    ``SchemeOperatorName`` values."""
    from cryptography.x509.oid import NameOID

    names = _ml_strings(scheme["SchemeOperatorName"], "SchemeOperatorName")
    orgs = [a.value for a in leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    if not orgs or not any(o in names for o in orgs):
        raise TrustListSignatureError(
            f"LoTE signing certificate organizationName {orgs!r} matches no "
            f"SchemeOperatorName value (clause 6.8)")
    if territory is not None:
        countries = [a.value for a in leaf.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)]
        if territory not in countries:
            raise TrustListSignatureError(
                f"LoTE signing certificate countryName {countries!r} does not match "
                f"the SchemeTerritory {territory!r} (clause 6.8)")


def _plus_months(dt: datetime, months: int) -> datetime:
    month = dt.month - 1 + months
    year = dt.year + month // 12
    month = month % 12 + 1
    return dt.replace(year=year, month=month,
                      day=min(dt.day, calendar.monthrange(year, month)[1]))


def _check_profile(
    trust_list: TrustList, lote_obj: Mapping[str, Any], profile: LoteProfile,
) -> None:
    scheme = lote_obj["ListAndSchemeInformation"]

    def fail(detail: str) -> None:
        raise TrustListProfileError(f"{profile.name}: {detail}")

    if trust_list.version != 1:
        fail(f"LoTEVersionIdentifier must be 1, got {trust_list.version!r}")
    if trust_list.tsl_type != profile.lote_type:
        fail(f"LoTEType must be {profile.lote_type!r}, got {trust_list.tsl_type!r}")
    detn = scheme.get("StatusDeterminationApproach")
    if detn not in profile.status_determination:
        fail(f"StatusDeterminationApproach must be one of "
             f"{list(profile.status_determination)!r}, got {detn!r}")
    rules = (_ml_uris(scheme["SchemeTypeCommunityRules"], "SchemeTypeCommunityRules")
             if "SchemeTypeCommunityRules" in scheme else [])
    if profile.scheme_rules not in rules:
        fail(f"SchemeTypeCommunityRules must include {profile.scheme_rules!r}, got {rules!r}")
    if trust_list.territory != profile.territory:
        fail(f"SchemeTerritory must be {profile.territory!r}, got {trust_list.territory!r}")
    if "HistoricalInformationPeriod" in scheme:
        fail("HistoricalInformationPeriod shall not be present")
    issue = datetime.fromisoformat(trust_list.issue_datetime or "")
    if trust_list.next_update is not None and (
            trust_list.next_update > _plus_months(issue, profile.max_update_months)):
        fail(f"NextUpdate {trust_list.next_update.isoformat()} is more than "
             f"{profile.max_update_months} months after ListIssueDateTime "
             f"{issue.isoformat()}")
    for provider in trust_list.providers:
        for svc in provider.services:
            if svc.service_status:
                fail(f"ServiceStatus shall not be used (service {svc.service_name!r} "
                     f"of {provider.name!r} carries {svc.service_status!r})")
            if svc.service_type not in profile.service_types:
                fail(f"ServiceTypeIdentifier {svc.service_type!r} (service "
                     f"{svc.service_name!r} of {provider.name!r}) is outside the "
                     f"profile's exclusive set {sorted(profile.service_types)!r}")
    # StatusStartingTime is date-validated in the parse but dropped by the typed
    # model; its *presence* violates the profile, which the wire object knows:
    entities = lote_obj.get("TrustedEntitiesList") or []
    for entity in entities:
        if not isinstance(entity, Mapping):
            continue
        for svc in entity.get("TrustedEntityServices") or []:
            info = svc.get("ServiceInformation") if isinstance(svc, Mapping) else None
            if isinstance(info, Mapping) and "StatusStartingTime" in info:
                fail("StatusStartingTime shall not be used")


# --------------------------------------------------------------------------- #
# walk
# --------------------------------------------------------------------------- #

def walk_lote(
    lote_url: str, *,
    lote_signer_certs: Sequence[Any],
    profile: LoteProfile | None = None,
    fetch: FetchLote = default_lote_fetch,
    select: Select | None = None,
    now: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lists: int = 8,
) -> TrustAnchorSet:
    """Fetch, verify and distil the LoTE at *lote_url* (plus one hop of pointed
    lists) into a :class:`TrustAnchorSet`.

    Trust is rooted in *lote_signer_certs* (caller-pinned — for the EU lists,
    the Commission's published list-signing certificates). The root list is
    verified with :func:`consume_lote` under *profile*; each **pointed** list is
    verified against the certificates its pointer vouched for (clause 6.3.13 —
    the same one-hop vouching model as :func:`~openvc.trustlist.walk_lotl`) and
    consumed without a profile. A list that cannot be fetched, verified, parsed,
    is expired, or is **closed** (``NextUpdate`` null, clause 6.3.15)
    contributes zero anchors and is recorded in ``problems`` — never silently
    trusted, never aborting the walk.

    *select* defaults to ``None`` (keep everything the profile admitted): the EU
    WRPAC/WRPRC profiles forbid ``ServiceStatus``, so the 119 612 lane's
    granted-status default would drop every anchor. Filter by
    ``service_types`` (e.g. only ``…/SvcType/WRPRC/Issuance``) when you need a
    subset. ``max_lists`` caps the total lists consumed (root + pointed)."""
    instant = now if now is not None else datetime.now(timezone.utc)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    problems: list[TrustListProblem] = []

    try:
        root_bytes = fetch(lote_url)
    except Exception as exc:                # root unreachable -> no anchors at all
        return TrustAnchorSet(
            anchors=(), problems=(TrustListProblem(lote_url, "fetch", str(exc)),))
    try:
        root = consume_lote(
            root_bytes if isinstance(root_bytes, str) else bytes(root_bytes),
            expected_signer_certs=lote_signer_certs, profile=profile,
            now=instant, max_bytes=max_bytes)
    except TrustListError as exc:
        return TrustAnchorSet(
            anchors=(), problems=(TrustListProblem(lote_url, _stage(exc), str(exc)),))
    stale = _staleness(root, instant)
    if stale:
        return TrustAnchorSet(
            anchors=(), problems=(TrustListProblem(lote_url, "expired", stale),))

    anchors: list[TrustServiceAnchor] = []
    for provider in root.providers:
        for svc in provider.services:
            if select is None or select.matches(svc):
                anchors.append(svc)

    visited = {lote_url}
    consumed = 1
    for pointer in root.pointers:
        if pointer.location in visited:
            continue                        # the EU profiles' self-pointer, or a repeat
        if (select is not None and select.territories is not None
                and (pointer.territory or "") not in select.territories):
            continue
        if consumed >= max_lists:
            problems.append(TrustListProblem(
                pointer.location, "consume",
                f"not followed: the {max_lists}-list cap was reached"))
            continue
        visited.add(pointer.location)
        consumed += 1
        try:
            pointed_bytes = fetch(pointer.location)
        except Exception as exc:
            problems.append(TrustListProblem(pointer.location, "fetch", str(exc)))
            continue
        try:
            pointed = consume_lote(
                pointed_bytes if isinstance(pointed_bytes, str) else bytes(pointed_bytes),
                expected_signer_certs=pointer.signer_certs, profile=None,
                now=instant, max_bytes=max_bytes)
        except TrustListError as exc:
            problems.append(TrustListProblem(pointer.location, _stage(exc), str(exc)))
            continue
        stale = _staleness(pointed, instant)
        if stale:
            problems.append(TrustListProblem(pointer.location, "expired", stale))
            continue
        for provider in pointed.providers:
            for svc in provider.services:
                if select is None or select.matches(svc):
                    anchors.append(svc)

    return TrustAnchorSet(anchors=tuple(anchors), problems=tuple(problems))


def _stage(exc: TrustListError) -> str:
    if isinstance(exc, TrustListProfileError):
        return "profile"
    if isinstance(exc, TrustListSignatureError):
        return "signature"
    if isinstance(exc, TrustListParseError):
        return "parse"
    return "consume"


def _staleness(trust_list: TrustList, now: datetime) -> str | None:
    if trust_list.next_update is None:
        return "the LoTE is closed (NextUpdate null, clause 6.3.15) — its scheme ceased"
    if trust_list.next_update < now:
        return f"NextUpdate {trust_list.next_update.isoformat()} is in the past"
    return None


__all__ = [
    "EU_WRPAC_PROVIDERS_PROFILE",
    "EU_WRPRC_PROVIDERS_PROFILE",
    "FetchLote",
    "LoteProfile",
    "LoteServiceType",
    "LoteType",
    "consume_lote",
    "default_lote_fetch",
    "parse_lote",
    "walk_lote",
]
