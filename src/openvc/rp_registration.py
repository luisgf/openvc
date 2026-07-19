"""
openvc.rp_registration — parse and verify an EUDI Wallet-Relying-Party Registration
Certificate (WRPRC).

Under CIR (EU) 2025/848 a wallet relying party carries two artifacts. The **access**
certificate (WRPAC, Art. 7 — mandatory) authenticates *who is asking*: it is X.509 and
lives in :mod:`openvc.rp_cert`. The **registration** certificate (WRPRC, Art. 8 —
optional per Member State) is the other half, and answers a different question:
**"were they registered to ask for this?"** It carries the relying party's registered
**entitlements** and the credentials/attributes it may request.

A WRPRC is *not* an X.509 certificate. ETSI TS 119 475 V1.2.1 clause 5.2 profiles it as
a signed **JWT** (``typ: rc-wrp+jwt``, clause 5.2.2) or **CWT** (``typ: rc-wrp+cwt``,
clause 5.2.3), so this module reads it over machinery openvc already has: the JOSE lane
for the JWT form (with the ``{ES256, ES384, EdDSA, Ed25519}`` allow-list applied
*before* any crypto, as everywhere else), the dependency-free CBOR/COSE codec for the
CWT form (:mod:`openvc.cbor` / :mod:`openvc.cose`, ADR-0005), and
:func:`openvc.x5c.validate_cert_chain` for the signer's chain against
**caller-provided** registrar anchors — openvc ships no root store.

Three things about the profile are worth knowing before you read the code, because each
one is a place the specification is thinner than it looks:

* **One WRPRC carries exactly one intended use.** TS5's data model nests an
  ``intendedUse[0..*]`` array, but clause 5.2.4 *flattens it away*: ``credentials``,
  ``purpose`` and ``intended_use_id`` are top-level payload claims. A relying party with
  several intended uses holds several WRPRCs.
* **``exp`` is optional** (Table 10). An absent expiry is conformant — revocation runs
  through the ``status`` claim (an IETF Token Status List, which
  :func:`openvc.status.check_token_status` resolves). The clause-5.2.4 GEN-5.2.4-08
  twelve-month ceiling therefore binds *only when ``exp`` is present*.
* **The CWT form has no claim-key mapping.** TS 119 475 presents its claim tables once,
  format-agnostically, with text field names; it never allocates CBOR integer labels for
  them, and TS 119 152-1 (CBOR AdES) is a forward reference. The envelope is fully
  specified (RFC 9052 + RFC 9360) and is implemented here; the claims map is read
  accepting *both* the RFC 8392 registered integer keys and text keys, which is the only
  reading available to an issuer today. Treat the CWT lane as provisional until a real
  artifact exists to pin.

**JAdES scope.** GEN-5.2.1-04 requires the JWT form to be signed as a **JAdES baseline
B-B** signature (ETSI TS 119 182-1). This implements a *verify subset* of B-B — the
signed-header profile (``typ``, allow-listed ``alg``, the ``x5c`` chain of clause 5.1.7
/ 5.1.8, a fail-closed ``crit``) and the chain validation — not a full JAdES library:
no signature-policy processing, no timestamps, no augmentation to higher levels. Note
that JAdES clause 5.1.11 mandates a *header* ``iat`` for signatures made after
2025-07-15 while TS 119 475 Table 5 omits it; since the two normative texts disagree,
the header ``iat`` is surfaced but **not** required — the security-bearing timestamps
are the payload's.

Two entry points, mirroring the library's trusted/untrusted split (and
:mod:`openvc.rp_cert`):

* :func:`parse_rp_registration_certificate` — read the claims WITHOUT establishing
  trust (UNTRUSTED, like ``peek_*``); for inspection only.
* :func:`verify_rp_registration_certificate` — validate the signature to
  caller-provided registrar anchors first, then parse; the result is safe to act on.

Two cross-checks turn the parsed object into an authorization decision:
:func:`check_matches_access_certificate` (this WRPRC describes the party that WRPAC
authenticates) and :func:`check_request_within_registration` (a DCQL request asks only
for what was registered).

Scope: parse + verify + cross-check. **NOT** registrar workflows or certificate
issuance — openvc is a consumer.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .errors import OpenvcError

__all__ = [
    "ENTITLEMENT_URI_PREFIX",
    "RelyingPartyRegistrationCertificate",
    "RequestableCredential",
    "RpRegistrationError",
    "WRPRC_CWT_TYP",
    "WRPRC_JWT_TYP",
    "WRPRC_POLICY_OID",
    "check_matches_access_certificate",
    "check_request_within_registration",
    "parse_rp_registration_certificate",
    "verify_rp_registration_certificate",
]


class RpRegistrationError(OpenvcError):
    """A relying-party registration certificate is malformed, does not validate to
    the provided anchors, or fails a registered-scope cross-check."""


# --------------------------------------------------------------------------- #
# The ETSI TS 119 475 V1.2.1 clause 5.2 profile
# --------------------------------------------------------------------------- #

WRPRC_JWT_TYP = "rc-wrp+jwt"       # clause 5.2.2 Table 5
WRPRC_CWT_TYP = "rc-wrp+cwt"       # clause 5.2.3 Table 6

#: Registered entitlements are URIs under this namespace (clause A.2; OID arc
#: ``0.4.0.19475.1``). GEN-5.2.4-03 requires at least one.
ENTITLEMENT_URI_PREFIX = "https://uri.etsi.org/19475/Entitlement/"

#: The WRPRC signature-policy OID (clause 6.1.3).
WRPRC_POLICY_OID = "0.4.0.19475.3.1"

# GEN-5.2.4-08: when `exp` is present it shall be no later than 12 months after the
# payload `iat`. Measured as 366 days so a leap year is not a spurious rejection.
_MAX_VALIDITY = timedelta(days=366)

# The German BMI Architekturkonzept defines a *different*, incompatible registration
# certificate under a near-identical media type. Half-parsing it would silently apply
# the wrong claim semantics, so it is named and refused.
_BMI_TYP = "rc-rp+jwt"

# JOSE header parameters this verifier processes, and so may accept in `crit`
# (RFC 7515 §4.1.11). `alg`/`typ`/`x5c` are IANA-registered and would not appear there;
# `iat` as a *header* parameter is JAdES-specific (TS 119 182-1 clause 5.1.11), and
# JAdES V1.1.1-era producers listed their non-registered parameters in `crit`. Anything
# outside this set fails closed — an unprocessed critical parameter is precisely what
# `crit` exists to stop being ignored.
_KNOWN_CRIT = frozenset({"alg", "typ", "x5c", "iat"})

# COSE header labels: RFC 9052 §3.1 (`alg`), RFC 9596 (`typ`), RFC 9360 §2 (`x5chain`).
_COSE_HDR_TYP = 16

# RFC 8392 §3.1 — the registered CWT claim keys, mapped onto their text names. TS 119
# 475 allocates no integer labels of its own, so its claims can only travel as text.
_CWT_REGISTERED_CLAIMS = {
    1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti",
}


@dataclass(frozen=True)
class RequestableCredential:
    """One entry of the registered ``credentials`` (clause 5.2.4 Table 9) or
    ``provides_attestations`` (Table 8) arrays — the credential *format* the relying
    party may ask for and, within it, the claim ``path``s it registered.

    ``claim_paths`` holds each registered path as a tuple; ``None`` inside a path is the
    DCQL array wildcard. An entry that registers **no** paths grants no attributes —
    see :func:`check_request_within_registration` for that fail-closed reading."""
    format: str | None
    meta: Mapping[str, Any]
    claim_paths: tuple[tuple[Any, ...], ...]
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class RelyingPartyRegistrationCertificate:
    """The parsed content of a WRPRC.

    ``subject_identifier`` is the ``sub`` claim: the ETSI EN 319 412-1 **semantic
    identifier** of the relying party (``VATES-B12345678``, ``LEIXG-…``, ``NTRDE-…``).
    Table 7 NOTE 2 is worth repeating — ``sub`` always identifies the relying party,
    *never* the intermediary, even when an intermediary presents the certificate. It is
    what :func:`check_matches_access_certificate` binds against the WRPAC.

    ``header`` and ``claims`` are the raw, verbatim protected header and claim set: the
    typed fields are a *view*, and a caller needing a claim this release does not model
    reads it from ``claims`` rather than going without. ``form`` is ``"jwt"`` or
    ``"cwt"``."""
    # identity (Table 7)
    subject_identifier: str | None
    trade_name: str | None
    legal_name: str | None
    given_name: str | None
    family_name: str | None
    country: str | None
    # registered scope (Tables 7–9)
    entitlements: tuple[str, ...]
    intended_use_id: str | None
    credentials: tuple[RequestableCredential, ...]
    provides_attestations: tuple[RequestableCredential, ...]
    purpose: tuple[Mapping[str, Any], ...]
    service_description: tuple[Mapping[str, Any], ...]
    # governance / contact (Tables 7, 10)
    policy_ids: tuple[str, ...]
    certificate_policy: str | None
    registry_uri: str | None
    privacy_policy: str | None
    info_uri: str | None
    support_uri: str | None
    supervisory_authority: Mapping[str, Any] | None
    intermediary: Mapping[str, Any] | None
    public_body: bool | None
    status: Mapping[str, Any] | None
    # temporal
    issued_at: datetime | None
    expires_at: datetime | None
    # provenance
    form: str
    header: Mapping[str, Any]
    claims: Mapping[str, Any]

    @property
    def intermediary_identifier(self) -> str | None:
        """The intermediary's semantic identifier, if the WRPRC is intermediated.

        The specification names this three ways — ``intermediary.sub`` (Table 10),
        and ``act.sub`` (GEN-5.2.4-09, which appears nowhere else). Both are read."""
        if self.intermediary is not None:
            sub = _str_or_none(self.intermediary.get("sub"))
            if sub is not None:
                return sub
        act = self.claims.get("act")
        return _str_or_none(act.get("sub")) if isinstance(act, Mapping) else None

    @property
    def intermediary_name(self) -> str | None:
        """The intermediary's common name. Table 10 spells the field ``sname`` while the
        Annex C example uses ``name``; since Annex C is what implementers copy but only
        the table is normative, both spellings are accepted."""
        if self.intermediary is None:
            return None
        return (_str_or_none(self.intermediary.get("sname"))
                or _str_or_none(self.intermediary.get("name")))


# --------------------------------------------------------------------------- #
# claim extraction
# --------------------------------------------------------------------------- #

def _str_or_none(value: Any) -> str | None:
    """A non-empty string, else ``None``. An empty/whitespace value normalises to
    ``None`` so a caller's ``is None`` guard is not defeated by ``''`` — and so a blank
    identifier can never satisfy a cross-check (see
    :func:`check_matches_access_certificate`)."""
    return value.strip() if isinstance(value, str) and value.strip() else None


def _mapping_or_none(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _str_tuple(value: Any, *, allow_scalar: bool = False) -> tuple[str, ...]:
    """The non-empty strings of a JSON array, in order.

    A scalar string is coerced only when *allow_scalar* — for ``entitlements``, where a
    malformed value silently becoming a one-element **grant** is a privilege question,
    it is not."""
    if isinstance(value, str):
        return (value.strip(),) if allow_scalar and value.strip() else ()
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(s.strip() for s in value if isinstance(s, str) and s.strip())


def _mapping_tuple(value: Any) -> tuple[Mapping[str, Any], ...]:
    """A localized-text array (``purpose``, ``srv_description``) as a flat tuple of
    objects. ``srv_description`` is typed as an array *of arrays* and the Annex C
    example nests it one level deeper than ``purpose``, so one level of nesting is
    flattened rather than dropped."""
    if not isinstance(value, (list, tuple)):
        return ()
    out: list[Mapping[str, Any]] = []
    for item in value:
        if isinstance(item, Mapping):
            out.append(item)
        elif isinstance(item, (list, tuple)):
            out.extend(sub for sub in item if isinstance(sub, Mapping))
    return tuple(out)


def _numeric_date(value: Any, *, field: str) -> datetime | None:
    """A NumericDate (RFC 7519 §2) as an aware UTC datetime, or ``None`` if absent.

    A present-but-unusable value fails closed rather than being dropped: a bool, a
    non-number, or a non-finite float (``NaN``/``Infinity`` — which ``json.loads``
    accepts, and against which every comparison is ``False``, i.e. *never expires*)
    raises instead of silently disabling the temporal check."""
    import math

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise RpRegistrationError(
            f"WRPRC {field} must be a finite NumericDate, got {value!r}")
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise RpRegistrationError(f"WRPRC {field} {value!r} is out of range") from exc


def _claim_paths(entry: Mapping[str, Any]) -> tuple[tuple[Any, ...], ...]:
    """The claim paths of one ``credentials`` entry.

    TS 119 475 names the member ``claim`` (singular, as in Annex C); the DCQL shape it
    mirrors (OpenID4VP 1.0) names it ``claims``. Both spellings are read — on the
    registration side so a producer following either does not silently register
    *nothing*, and on the request side so a query is never under-read into looking
    narrower than it is."""
    raw = entry.get("claim")
    if raw is None:
        raw = entry.get("claims")
    if not isinstance(raw, (list, tuple)):
        return ()
    paths: list[tuple[Any, ...]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        path = item.get("path")
        if isinstance(path, (list, tuple)):
            paths.append(tuple(path))
        elif isinstance(path, str):          # B.2.10 types `path` as a string
            paths.append((path,))
    return tuple(paths)


def _requestable(value: Any) -> tuple[RequestableCredential, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    out = []
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        out.append(RequestableCredential(
            format=_str_or_none(entry.get("format")),
            meta=_mapping_or_none(entry.get("meta")) or {},
            claim_paths=_claim_paths(entry),
            raw=entry,
        ))
    return tuple(out)


def _build(
    header: Mapping[str, Any], claims: Mapping[str, Any], *, form: str,
) -> RelyingPartyRegistrationCertificate:
    public_body = claims.get("public_body")
    return RelyingPartyRegistrationCertificate(
        subject_identifier=_str_or_none(claims.get("sub")),
        trade_name=_str_or_none(claims.get("name")),
        legal_name=_str_or_none(claims.get("sub_ln")),
        given_name=_str_or_none(claims.get("sub_gn")),
        family_name=_str_or_none(claims.get("sub_fn")),
        country=_str_or_none(claims.get("country")),
        entitlements=_str_tuple(claims.get("entitlements")),
        intended_use_id=_str_or_none(claims.get("intended_use_id")),
        credentials=_requestable(claims.get("credentials")),
        provides_attestations=_requestable(claims.get("provides_attestations")),
        purpose=_mapping_tuple(claims.get("purpose")),
        service_description=_mapping_tuple(claims.get("srv_description")),
        policy_ids=_str_tuple(claims.get("policy_id"), allow_scalar=True),
        certificate_policy=_str_or_none(claims.get("certificate_policy")),
        registry_uri=_str_or_none(claims.get("registry_uri")),
        privacy_policy=_str_or_none(claims.get("privacy_policy")),
        info_uri=_str_or_none(claims.get("info_uri")),
        support_uri=_str_or_none(claims.get("support_uri")),
        supervisory_authority=_mapping_or_none(claims.get("supervisory_authority")),
        intermediary=_mapping_or_none(claims.get("intermediary")),
        public_body=public_body if isinstance(public_body, bool) else None,
        status=_mapping_or_none(claims.get("status")),
        issued_at=_numeric_date(claims.get("iat"), field="iat"),
        expires_at=_numeric_date(claims.get("exp"), field="exp"),
        form=form,
        header=header,
        claims=claims,
    )


# --------------------------------------------------------------------------- #
# envelope: the JWT (JAdES B-B subset) and CWT (COSE_Sign1) forms
# --------------------------------------------------------------------------- #

def _reject_unknown_crit(header: Mapping[str, Any]) -> None:
    """RFC 7515 §4.1.11 — a verifier MUST reject a JWS whose ``crit`` names an
    extension it does not process.

    The plain-JWS lanes (:func:`openvc.proof._verify_common.reject_unknown_crit`)
    process no extensions at all and so reject ``crit`` outright. This lane cannot: a
    JAdES V1.1.1-era producer listed its non-registered header parameters there, so the
    check allow-lists exactly the parameters this verifier *understands*
    (:data:`_KNOWN_CRIT`) and fails closed on the rest."""
    if "crit" not in header:
        return
    crit = header["crit"]
    if not isinstance(crit, list) or not crit or not all(isinstance(c, str) for c in crit):
        raise RpRegistrationError("WRPRC 'crit' must be a non-empty array of strings")
    unknown = [c for c in crit if c not in _KNOWN_CRIT]
    if unknown:
        raise RpRegistrationError(
            f"WRPRC marks header parameter(s) {unknown!r} critical, which this verifier "
            f"does not process (understood: {sorted(_KNOWN_CRIT)})")
    missing = [c for c in crit if c not in header]
    if missing:
        raise RpRegistrationError(
            f"WRPRC 'crit' names header parameter(s) {missing!r} that are not present")


def _check_alg(alg: Any) -> str:
    """Allow-list the signature algorithm BEFORE any crypto runs — the invariant the
    whole library keeps. TS 119 475 defers the algorithm set to TS 119 182-1 clause
    5.1.2, which requires an IANA-registered identifier and *recommends* the TS 119 312
    set; openvc's ``{ES256, ES384, EdDSA, Ed25519}`` is a subset of it, so RS*/HS*/
    ``none`` never reach a verify call."""
    from .proof.vc_jwt import ALLOWED_ALGS

    if not isinstance(alg, str) or alg not in ALLOWED_ALGS:
        raise RpRegistrationError(
            f"WRPRC alg {alg!r} is not permitted (need one of {sorted(ALLOWED_ALGS)})")
    return alg


def _check_typ(typ: Any, expected: str) -> None:
    if typ == expected:
        return
    if typ == _BMI_TYP:
        raise RpRegistrationError(
            f"token typ {_BMI_TYP!r} is the German BMI Architekturkonzept registration "
            f"certificate, a different profile with different claim names — not the "
            f"ETSI TS 119 475 WRPRC ({expected!r}) this module parses")
    raise RpRegistrationError(f"WRPRC typ must be {expected!r}, got {typ!r}")


def _jwt_envelope(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split + profile-check the JWT form, WITHOUT verifying the signature."""
    from .proof._jws import parse_compact
    from .proof.errors import ProofError

    try:
        header, claims, signing_input, signature = parse_compact(token)
    except ProofError as exc:
        raise RpRegistrationError(f"WRPRC is not a valid compact JWS: {exc}") from exc
    _check_typ(header.get("typ"), WRPRC_JWT_TYP)
    _check_alg(header.get("alg"))
    _reject_unknown_crit(header)
    return header, claims, signing_input, signature


def _cwt_envelope(data: bytes) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """Parse + profile-check the CWT form (a ``COSE_Sign1`` whose payload is a CBOR
    claims map), WITHOUT verifying the signature.

    The COSE lane's own hardening applies: ``alg`` is read from the **protected** header
    only (never from the unsigned one), and an unhandled critical label fails closed
    (:mod:`openvc.cose`)."""
    from . import cbor, cose

    try:
        sign1 = cose.parse_sign1(cbor.decode(data))
    except (cbor.CborError, cose.CoseError) as exc:
        raise RpRegistrationError(f"WRPRC is not a valid COSE_Sign1: {exc}") from exc

    typ = sign1.protected_header.get(_COSE_HDR_TYP)
    if isinstance(typ, (bytes, bytearray)):
        typ = bytes(typ).decode("utf-8", "replace")
    _check_typ(typ, WRPRC_CWT_TYP)

    try:
        alg = sign1.alg
    except cose.CoseError as exc:
        raise RpRegistrationError(f"WRPRC COSE header: {exc}") from exc
    if alg not in cose.COSE_ALG_TO_JOSE:
        raise RpRegistrationError(
            f"WRPRC COSE alg {alg!r} is not permitted (need one of "
            f"{sorted(cose.COSE_ALG_TO_JOSE)})")

    if sign1.payload is None:
        raise RpRegistrationError("WRPRC COSE_Sign1 has a detached payload (no claims)")
    try:
        raw_claims = cbor.decode(sign1.payload)
    except cbor.CborError as exc:
        raise RpRegistrationError(f"WRPRC CWT claims are not valid CBOR: {exc}") from exc
    if not isinstance(raw_claims, dict):
        raise RpRegistrationError("WRPRC CWT claims must be a CBOR map")
    return dict(sign1.protected_header), _normalise_cwt_claims(raw_claims), sign1


def _normalise_cwt_claims(raw: Mapping[Any, Any]) -> dict[str, Any]:
    """Map a CWT claims map onto the text claim names so both forms of a WRPRC produce
    the same typed object.

    TS 119 475 allocates no CBOR labels for its own claims, so they can only travel as
    text keys; the RFC 8392 registered set may travel either way and is translated. A
    registered integer key that **collides** with an already-present text key fails
    closed — two spellings of ``exp`` in one token is a parser-differential wedge, not
    something to resolve by last-write-wins."""
    claims: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(key, bool):
            continue
        name = _CWT_REGISTERED_CLAIMS.get(key) if isinstance(key, int) else None
        if name is None:
            if not isinstance(key, str):
                continue                    # an unregistered integer label: not ours to read
            name = key
        if name in claims:
            raise RpRegistrationError(
                f"WRPRC CWT carries claim {name!r} twice (integer and text key)")
        claims[name] = value
    return claims


def _chain_from_jwt(header: Mapping[str, Any]) -> list[Any]:
    from .x5c import X5cError, load_x5c_chain

    x5c = header.get("x5c")
    if x5c is None:
        raise RpRegistrationError(
            "WRPRC JWS header has no 'x5c' chain to anchor the registrar "
            "(TS 119 475 Table 5; TS 119 182-1 clause 5.1.7 requires a signing-certificate "
            "reference)")
    try:
        return load_x5c_chain(x5c)
    except X5cError as exc:
        raise RpRegistrationError(f"WRPRC 'x5c': {exc}") from exc


def _chain_from_cwt(sign1: Any) -> list[Any]:
    from . import cose
    from .x5c import X5cError, load_der_chain

    try:
        ders = cose.x5chain_ders(sign1)
    except cose.CoseError as exc:
        raise RpRegistrationError(
            f"WRPRC COSE_Sign1 has no usable x5chain to anchor the registrar: {exc}") from exc
    try:
        return load_der_chain(ders)
    except X5cError as exc:
        raise RpRegistrationError(f"WRPRC x5chain: {exc}") from exc


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #

def parse_rp_registration_certificate(
    token: str | bytes,
) -> RelyingPartyRegistrationCertificate:
    """Parse a WRPRC's claims WITHOUT establishing trust.

    *token* is the JWT form (a compact-JWS ``str``) or the CWT form (``bytes``: a
    ``COSE_Sign1``). The signed-header profile is still enforced — ``typ``, the
    algorithm allow-list, a fail-closed ``crit`` — because a token that is not *shaped*
    like a WRPRC should not be reported as one; but **the signature is not checked and
    no chain is validated**.

    UNTRUSTED — the returned entitlements are whatever the bytes claimed. Use it only to
    inspect a token (e.g. to read its ``sub`` before choosing anchors); call
    :func:`verify_rp_registration_certificate` before making any authorization decision
    on the registered scope it names.
    """
    if isinstance(token, str):
        header, claims, _, _ = _jwt_envelope(token)
        return _build(header, claims, form="jwt")
    if isinstance(token, (bytes, bytearray)):
        header, claims, _ = _cwt_envelope(bytes(token))
        return _build(header, claims, form="cwt")
    raise RpRegistrationError(
        "WRPRC must be a compact-JWS string (rc-wrp+jwt) or COSE_Sign1 bytes (rc-wrp+cwt)")


def _check_temporal(
    reg: RelyingPartyRegistrationCertificate, *, now: datetime | None, leeway_s: int,
    max_validity: timedelta | None, require_expiry: bool,
) -> None:
    if now is None:
        instant = datetime.now(timezone.utc)
    elif now.tzinfo is None:                        # a naive now is taken as UTC, not
        instant = now.replace(tzinfo=timezone.utc)  # silently as the host's local time
    else:
        instant = now.astimezone(timezone.utc)
    leeway = timedelta(seconds=max(0, leeway_s))

    if reg.expires_at is None and require_expiry:
        raise RpRegistrationError(
            "WRPRC has no 'exp' (conformant per TS 119 475 Table 10, but this call "
            "required one) — check the 'status' claim for revocation instead")
    if reg.expires_at is not None and instant - leeway > reg.expires_at:
        raise RpRegistrationError(f"WRPRC expired at {reg.expires_at.isoformat()}")

    not_before = _numeric_date(reg.claims.get("nbf"), field="nbf") or reg.issued_at
    if not_before is not None and instant + leeway < not_before:
        raise RpRegistrationError(f"WRPRC is not valid before {not_before.isoformat()}")

    # GEN-5.2.4-08 — binds only when `exp` is present.
    if (max_validity is not None and reg.expires_at is not None
            and reg.issued_at is not None
            and reg.expires_at - reg.issued_at > max_validity):
        raise RpRegistrationError(
            f"WRPRC validity {reg.expires_at - reg.issued_at} exceeds the {max_validity} "
            f"maximum (TS 119 475 GEN-5.2.4-08)")


def verify_rp_registration_certificate(
    token: str | bytes,
    *,
    trust_anchors: Sequence[Any],
    intermediates: Sequence[Any] = (),
    now: datetime | None = None,
    leeway_s: int = 60,
    required_eku: str | None = None,
    max_validity: timedelta | None = _MAX_VALIDITY,
    require_expiry: bool = False,
    require_entitlement: bool = True,
) -> RelyingPartyRegistrationCertificate:
    """Verify a WRPRC and return its parsed content.

    In order: the signed-header profile (``typ``, the ``{ES256, ES384, EdDSA, Ed25519}``
    allow-list applied **before** any crypto, a fail-closed ``crit``); the signer's chain
    — ``x5c`` for the JWT form, ``x5chain`` for the CWT form, plus any caller-supplied
    *intermediates* — path-validated to *trust_anchors* (the registrar roots) by
    ``cryptography``'s verifier; then the **signature** against that chain's leaf key;
    then the temporal claims and the entitlement floor.

    Policy knobs, all defaulting to the specification's own reading:

    * *required_eku* — additionally require this EKU OID on the signing leaf.
    * *max_validity* — the GEN-5.2.4-08 twelve-month ceiling, applied only when ``exp``
      is present. ``None`` disables it.
    * *require_expiry* — ``exp`` is **optional** in TS 119 475 (Table 10), so this
      defaults to ``False``. Set it if your policy refuses a certificate that can only
      be retired through revocation.
    * *require_entitlement* — GEN-5.2.4-03 requires at least one registered entitlement;
      a WRPRC without one authorizes nothing anyway.

    **This proves the token was signed by a certificate that chains to your anchors — it
    does NOT, by itself, prove the signer was entitled to register *this* relying
    party.** As with :func:`openvc.rp_cert.verify_rp_access_certificate`, if your anchors
    certify end-entities beyond registrars, pass *required_eku* (or gate on the returned
    ``header``) to distinguish one. Trust is anchored through the chain, not through
    ``iss`` — TS 119 475 defines no ``iss`` claim at all. openvc ships no root store.

    It also does **not** check the ``status`` claim: a WRPRC is revoked through the IETF
    Token Status List, which :func:`openvc.status.check_token_status` resolves. That
    needs network access, so it stays an explicit, separate call.

    Raises :class:`RpRegistrationError` on a malformed token, a rejected header, a
    path-validation failure, a bad signature, or a failed policy check.
    """
    from .x5c import X5cError, leaf_public_jwk, validate_cert_chain

    if isinstance(trust_anchors, (str, bytes)) or not isinstance(trust_anchors, Iterable):
        raise RpRegistrationError(
            "trust_anchors must be a sequence of registrar roots, not a single value")
    if isinstance(intermediates, (str, bytes)) or not isinstance(intermediates, Iterable):
        raise RpRegistrationError("intermediates must be a sequence of certificates")
    if now is not None and not isinstance(now, datetime):
        raise RpRegistrationError("now must be a datetime or None")

    anchors = _load_certs(trust_anchors, "trust_anchors")
    if not anchors:
        raise RpRegistrationError("no trust anchors given (a sequence of registrar roots)")
    extra = _load_certs(intermediates, "intermediates")

    sign1: Any = None
    if isinstance(token, str):
        header, claims, signing_input, signature = _jwt_envelope(token)
        chain = _chain_from_jwt(header)
        form = "jwt"
    elif isinstance(token, (bytes, bytearray)):
        header, claims, sign1 = _cwt_envelope(bytes(token))
        chain = _chain_from_cwt(sign1)
        signing_input = signature = b""
        form = "cwt"
    else:
        raise RpRegistrationError(
            "WRPRC must be a compact-JWS string (rc-wrp+jwt) or COSE_Sign1 bytes (rc-wrp+cwt)")

    try:
        validate_cert_chain(chain[0], chain[1:] + extra, trust_anchors=anchors, now=now)
    except X5cError as exc:
        raise RpRegistrationError(
            f"WRPRC signing certificate did not validate to a trust anchor: {exc}") from exc

    if required_eku is not None:
        _require_eku(chain[0], required_eku)

    try:
        public_jwk = leaf_public_jwk(chain[0])
    except X5cError as exc:
        raise RpRegistrationError(f"WRPRC signing certificate: {exc}") from exc

    _verify_signature(
        form, header, public_jwk,
        signing_input=signing_input, signature=signature, sign1=sign1)

    reg = _build(header, claims, form=form)
    _check_temporal(reg, now=now, leeway_s=leeway_s, max_validity=max_validity,
                    require_expiry=require_expiry)
    if require_entitlement and not reg.entitlements:
        raise RpRegistrationError(
            "WRPRC registers no entitlements (TS 119 475 GEN-5.2.4-03 requires at least "
            "one) — it authorizes nothing")
    return reg


def _verify_signature(
    form: str, header: Mapping[str, Any], public_jwk: dict[str, Any], *,
    signing_input: bytes, signature: bytes, sign1: Any,
) -> None:
    from .keys import KeyBackendError, verify_signature

    if form == "jwt":
        try:
            ok = verify_signature(
                alg=_check_alg(header.get("alg")), public_jwk=public_jwk,
                signing_input=signing_input, signature=signature)
        except KeyBackendError as exc:
            raise RpRegistrationError(f"WRPRC signature could not be checked: {exc}") from exc
    else:
        from . import cose
        try:
            ok = cose.verify_sign1(sign1, public_jwk=public_jwk)
        except (cose.CoseError, KeyBackendError) as exc:
            raise RpRegistrationError(f"WRPRC signature could not be checked: {exc}") from exc
    if not ok:
        raise RpRegistrationError("WRPRC signature verification failed")


def _load_certs(certs: Iterable[Any], what: str) -> list[Any]:
    """Coerce each entry through the same loader :mod:`openvc.rp_cert` uses, so a
    registrar anchor may be an ``x509.Certificate``, DER/PEM bytes, or a base64 string —
    and a bad entry is a typed error, not a silent drop that would fail-open the set."""
    from .rp_cert import RpCertError, _load_cert

    loaded = []
    for entry in certs:
        try:
            loaded.append(_load_cert(entry))
        except RpCertError as exc:
            raise RpRegistrationError(f"{what}: {exc}") from exc
    return loaded


def _require_eku(leaf: Any, required_eku: str) -> None:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        eku = leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise RpRegistrationError(
            f"WRPRC signing certificate has no extendedKeyUsage (needs {required_eku!r})")
    if required_eku not in {oid.dotted_string for oid in eku}:
        raise RpRegistrationError(
            f"WRPRC signing certificate lacks the required extendedKeyUsage {required_eku!r}")


# --------------------------------------------------------------------------- #
# cross-checks — from "a valid registration" to "authorized for this request"
# --------------------------------------------------------------------------- #

def check_matches_access_certificate(
    registration: RelyingPartyRegistrationCertificate,
    access: Any,
    *,
    match_trade_name: bool = False,
) -> None:
    """Bind a verified WRPRC to the verified WRPAC that authenticated the caller.

    Both artifacts must name the **same** relying party: the WRPRC's ``sub`` — its ETSI
    EN 319 412-1 semantic identifier — must equal the WRPAC's ``entity_identifier``
    (subject ``organizationIdentifier``, the same namespace). That is GEN-5.1.1-04.
    Without this bind, an attacker presenting their own valid WRPAC could pair it with
    *someone else's* valid WRPRC and inherit that party's registered scope.

    An identifier missing on **either** side is a failure, never a match: comparing two
    absent values would make ``None == None`` a successful bind — a fail-open hole
    exactly where the check exists to close one.

    *match_trade_name* additionally requires the WRPRC's ``name`` to equal the WRPAC's
    ``trade_name``. It is off by default: the two are free-text and legitimately differ
    in punctuation or legal suffix, so a mismatch is weak evidence and would produce
    false rejections. Note the comparison is intentionally on the *identifier*, which is
    registry-controlled.

    *access* is a :class:`~openvc.rp_cert.RelyingPartyAccessCertificate` (or anything
    exposing ``entity_identifier`` / ``trade_name``). Raises
    :class:`RpRegistrationError` on any mismatch; returns ``None`` on success.
    """
    theirs = _str_or_none(getattr(access, "entity_identifier", None))
    ours = registration.subject_identifier
    if ours is None or theirs is None:
        raise RpRegistrationError(
            "cannot bind WRPRC to WRPAC: the relying-party identifier is missing on "
            f"{'the WRPRC (sub)' if ours is None else 'the WRPAC (organizationIdentifier)'}")
    if ours != theirs:
        raise RpRegistrationError(
            f"WRPRC subject identifier {ours!r} does not match the WRPAC's {theirs!r} — "
            f"these are two different relying parties")

    if not match_trade_name:
        return
    their_name = _str_or_none(getattr(access, "trade_name", None))
    if registration.trade_name is None or their_name is None:
        raise RpRegistrationError(
            "cannot compare trade names: missing on "
            f"{'the WRPRC' if registration.trade_name is None else 'the WRPAC'}")
    if registration.trade_name != their_name:
        raise RpRegistrationError(
            f"WRPRC trade name {registration.trade_name!r} does not match the WRPAC's "
            f"{their_name!r}")


def _path_covered(registered: tuple[Any, ...], requested: Sequence[Any]) -> bool:
    """Whether a registered claim path covers a requested one.

    A registered path covers a requested path when it is a **prefix** of it under
    element-wise matching: registering the container ``["address"]`` covers
    ``["address", "locality"]``, because a DCQL selection of ``address`` already returns
    the whole object — so this is not a widening. ``None`` (the DCQL array wildcard) in
    the *registered* path matches any element; a ``None`` in the *requested* path is
    only covered by a registered ``None``, so registering index ``2`` never grants
    "every element"."""
    if len(registered) > len(requested):
        return False
    for reg_el, req_el in zip(registered, requested):
        if reg_el is None:
            continue
        # `True == 1` in Python: without the bool guard, a registered index 1 would
        # cover a requested `True` and vice versa.
        if reg_el != req_el or isinstance(reg_el, bool) is not isinstance(req_el, bool):
            return False
    return True


def _meta_covered(registered: Mapping[str, Any], requested: Mapping[str, Any]) -> bool:
    """Whether a registered ``meta`` covers a requested one.

    Every constraint the request carries must be present in the registration and no
    wider there: list values (``vct_values``, ``doctype_values``) must be a subset,
    scalars must be equal. A request carrying a constraint the registration does not
    mention is **not** covered — otherwise a party registered for ``vct:Diploma`` could
    request ``vct:BankAccount`` under the same entry. A request carrying *no*
    constraints is unrestricted, so it is covered only by an equally unrestricted
    registration.

    Subset testing is deliberately done with ``in`` (equality) rather than by building
    ``set``s: a ``meta`` value is attacker-influenced JSON and may hold unhashable
    members (an object, an array), which would make the set construction raise a bare
    ``TypeError`` straight past this library's error family."""
    if not requested:
        return not registered
    for key, want in requested.items():
        if key not in registered:
            return False
        have = registered[key]
        if isinstance(want, (list, tuple)):
            if not isinstance(have, (list, tuple)) or not all(w in have for w in want):
                return False
        elif isinstance(have, (list, tuple)):
            if want not in have:
                return False
        elif want != have:
            return False
    return True


def check_request_within_registration(
    registration: RelyingPartyRegistrationCertificate,
    dcql_query: Mapping[str, Any],
    *,
    intended_use_id: str | None = None,
) -> None:
    """Check a presentation request against the registered scope: every credential and
    attribute the DCQL query asks for must appear in the WRPRC's ``credentials``.

    *dcql_query* is the OpenID4VP 1.0 ``dcql_query`` the relying party sent — the same
    object :func:`openvc.verify_vp_token` consumes. For each of its credential queries
    this requires a registered entry of the same ``format`` whose ``meta`` covers the
    requested one, and every requested claim ``path`` to fall inside that entry's
    registered paths (a registered container covers its members; see
    :func:`_path_covered`).

    A WRPRC carries **one** intended use (clause 5.2.4 flattens TS5's nested model), so
    *intended_use_id* is an optional assertion rather than a selector: pass it and the
    certificate's own ``intended_use_id`` must equal it. Note the claim is itself
    optional in the profile — a WRPRC that omits it cannot satisfy this assertion.

    **Fail-closed by construction.** A request that names no claims is asking for
    *everything* in that credential and is refused unless the registration is equally
    unrestricted; a registered entry that lists no claim paths grants no attributes.
    Both readings deny rather than widen — the opposite default would turn an incomplete
    registration into a blanket entitlement.

    This is an *authorization* check on top of verification: call it only on a WRPRC
    that :func:`verify_rp_registration_certificate` accepted and
    :func:`check_matches_access_certificate` bound to the requesting party. Raises
    :class:`RpRegistrationError` on anything out of scope; returns ``None`` on success.
    """
    if intended_use_id is not None and registration.intended_use_id != intended_use_id:
        raise RpRegistrationError(
            f"WRPRC registers intended use {registration.intended_use_id!r}, not "
            f"{intended_use_id!r}")
    if not isinstance(dcql_query, Mapping):
        raise RpRegistrationError("dcql_query must be a JSON object")
    queries = dcql_query.get("credentials")
    if not isinstance(queries, (list, tuple)) or not queries:
        raise RpRegistrationError("dcql_query has no 'credentials' array to check")

    for index, query in enumerate(queries):
        if not isinstance(query, Mapping):
            raise RpRegistrationError(f"dcql_query credential #{index} is not an object")
        label = _str_or_none(query.get("id")) or f"#{index}"
        fmt = _str_or_none(query.get("format"))
        want_meta = _mapping_or_none(query.get("meta")) or {}
        candidates = [
            c for c in registration.credentials
            if c.format == fmt and _meta_covered(c.meta, want_meta)
        ]
        if not candidates:
            raise RpRegistrationError(
                f"credential query {label!r} asks for format {fmt!r} with meta "
                f"{dict(want_meta)!r}, which this WRPRC does not register")

        wanted = _claim_paths(query)
        if not wanted:
            if any(not c.claim_paths for c in candidates):
                continue                     # unrestricted request, unrestricted grant
            raise RpRegistrationError(
                f"credential query {label!r} names no claims (asks for every attribute), "
                f"but this WRPRC registers an explicit attribute list")
        granted = tuple(p for c in candidates for p in c.claim_paths)
        for path in wanted:
            if not any(_path_covered(reg, path) for reg in granted):
                raise RpRegistrationError(
                    f"credential query {label!r} requests claim path {list(path)!r}, "
                    f"which this WRPRC does not register")
