"""
openvc.trustlist.parse — parse an ETSI TS 119 612 Trusted List XML into typed
records, with a **hardened, stdlib-only** parser.

The parser runs on **attacker-influenced bytes** (it must run before the XML
signature is verified — it is what finds the signer certs), so it is hardened:

* **No DTD / DOCTYPE.** An ``expat`` ``StartDoctypeDeclHandler`` rejects any
  DOCTYPE, which blocks both XXE (external entities) and entity-expansion bombs
  (billion laughs) — those require a DTD to declare entities. ``expat`` does not
  fetch external resources on its own either.
* **Bounded input.** A configurable byte cap (default 16 MiB — a national TL is a
  few MB) rejects an oversize document before parsing.
* **Namespace by URI, never by prefix.** Elements are matched on ``{uri}local``.
* **Date-times fail closed.** ``NextUpdate`` is read as a UTC ``datetime`` of the
  ``YYYY-MM-DDThh:mm:ssZ`` form clause 5.1.3 mandates (a fraction tolerated,
  ``+00:00`` accepted for ``Z``) or as *null* (a closed TL, clause 5.3.15); any
  other value is a :class:`TrustListParseError`, never ``None`` — the walk would
  otherwise read it as unbounded validity (#389, #407).

No signature logic lives here (that is an injected callback — see
:mod:`openvc.trustlist.consume`).
"""
from __future__ import annotations

import base64
import re
import xml.parsers.expat as expat
from datetime import datetime, timezone
from typing import Any
from xml.etree.ElementTree import Element, TreeBuilder

from ..proof._verify_common import safe_repr
from .errors import TrustListParseError
from .model import TrustList, TrustServiceAnchor, TrustServiceProvider, TslPointer

# ETSI TS 119 612 / W3C namespaces.
TSL = "http://uri.etsi.org/02231/v2#"
ADD = "http://uri.etsi.org/02231/v2/additionaltypes#"
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"

DEFAULT_MAX_BYTES = 16 * 1024 * 1024        # 16 MiB — generous for a national TL
DEFAULT_MAX_ELEMENTS = 500_000              # ADR-0003 D4: bound the element count too

# Clause 5.1.3's date-time shape: ISO 8601, UTC, second precision, the ``Z``
# designator — ``lote._DATETIME_Z`` (the LoTE lane's clause 6.1.3 twin, kept there
# unchanged; neither lane imports the other's private name) with two tolerances:
# a fraction of a second, and ``+00:00`` as the offset spelling of UTC. ASCII
# digits only, and the fields are read by this regex rather than by the
# interpreter's ``fromisoformat`` (which widened in 3.11: basic format, any
# separator, short offsets, and ``24:00:00`` rolled to the next day), so the
# accept set is the same on every interpreter.
_DATETIME_UTC = re.compile(
    r"(?P<Y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})T(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})"
    r"(?P<frac>\.\d+)?(?:Z|\+00:00)",
    re.ASCII)

_NS_SEP = "\x01"


def _q(local: str, ns: str = TSL) -> str:
    return f"{{{ns}}}{local}"


def parse_trust_list(xml: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES) -> TrustList:
    """Parse a Trusted List (or the LOTL) XML document into a :class:`TrustList`.

    Hardened against XXE / entity-expansion (no DTD) and oversize input. Raises
    :class:`TrustListParseError` on malformed, oversize, or DTD-bearing XML."""
    root = _hardened_parse(xml, max_bytes=max_bytes)
    if root.tag != _q("TrustServiceStatusList"):
        raise TrustListParseError(
            f"root element is {root.tag!r}, not a TrustServiceStatusList")

    scheme = root.find(_q("SchemeInformation"))
    tsl_type = _text(scheme, _q("TSLType")) if scheme is not None else None
    operator = None
    territory = None
    seq = None
    version = None
    issue = None
    next_update = None
    pointers: list[TslPointer] = []
    if scheme is not None:
        operator = _localized_name(scheme.find(_q("SchemeOperatorName")))
        territory = _text(scheme, _q("SchemeTerritory"))
        seq = _int(_text(scheme, _q("TSLSequenceNumber")))
        version = _int(_text(scheme, _q("TSLVersionIdentifier")))
        issue = _text(scheme, _q("ListIssueDateTime"))
        # Clause 5.3.15: a null NextUpdate (no <dateTime>, or none at all) marks a
        # **closed** TL — kept as None for the walk to stage; a malformed one raises.
        nu = scheme.find(_q("NextUpdate"))
        next_update = (_parse_datetime(_text(nu, _q("dateTime")), "NextUpdate")
                       if nu is not None else None)
        ptrs = scheme.find(_q("PointersToOtherTSL"))
        if ptrs is not None:
            for op in ptrs.findall(_q("OtherTSLPointer")):
                pointer = _parse_pointer(op)
                if pointer is not None:
                    pointers.append(pointer)

    providers: list[TrustServiceProvider] = []
    tsp_list = root.find(_q("TrustServiceProviderList"))
    if tsp_list is not None:
        for tsp in tsp_list.findall(_q("TrustServiceProvider")):
            providers.append(_parse_provider(tsp, territory))

    return TrustList(
        tsl_type=tsl_type, scheme_operator=operator, territory=territory,
        sequence_number=seq, issue_datetime=issue, next_update=next_update,
        pointers=tuple(pointers), providers=tuple(providers), version=version)


# --------------------------------------------------------------------------- #
# Hardened XML parse
# --------------------------------------------------------------------------- #

def _hardened_parse(xml: bytes, *, max_bytes: int,
                    max_elements: int = DEFAULT_MAX_ELEMENTS) -> Element:
    if not isinstance(xml, (bytes, bytearray)):
        raise TrustListParseError(
            f"trust list must be bytes, got {type(xml).__name__}")
    if len(xml) > max_bytes:
        raise TrustListParseError(
            f"trust list is {len(xml)} bytes, over the {max_bytes}-byte cap")

    builder = TreeBuilder()
    parser = expat.ParserCreate(namespace_separator=_NS_SEP)
    parser.buffer_text = True

    def _forbid_dtd(*_a: Any) -> None:
        raise TrustListParseError("DOCTYPE/DTD is not allowed in a trust list")

    count = [0]

    def _start(name: str, attrs: dict) -> None:
        count[0] += 1
        if count[0] > max_elements:            # ADR-0003 D4: a max-bytes cap AND an element cap
            raise TrustListParseError(
                f"trust list exceeds the {max_elements}-element cap")
        builder.start(_qname(name), {_qname(k): v for k, v in attrs.items()})

    parser.StartDoctypeDeclHandler = _forbid_dtd
    parser.StartElementHandler = _start
    parser.EndElementHandler = lambda name: builder.end(_qname(name))
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(bytes(xml), True)
    except TrustListParseError:
        raise
    except expat.ExpatError as exc:
        raise TrustListParseError(f"malformed trust list XML: {exc}") from exc
    return builder.close()


def _qname(name: str) -> str:
    """Reformat expat's ``"uri<sep>local"`` into ElementTree's ``"{uri}local"``."""
    if _NS_SEP in name:
        uri, local = name.split(_NS_SEP, 1)
        return f"{{{uri}}}{local}"
    return name


# --------------------------------------------------------------------------- #
# Element extraction
# --------------------------------------------------------------------------- #

def _parse_pointer(op: Element) -> TslPointer | None:
    location = _text(op, _q("TSLLocation"))
    if not location:
        return None
    certs = _certs_under(op.find(_q("ServiceDigitalIdentities")))
    territory = None
    tsl_type = None
    mime_type = None
    add = op.find(_q("AdditionalInformation"))
    if add is not None:
        for other in add.findall(_q("OtherInformation")):
            terr = other.find(_q("SchemeTerritory"))
            if terr is not None and terr.text:
                territory = terr.text.strip()
            typ = other.find(_q("TSLType"))
            if typ is not None and typ.text:
                tsl_type = typ.text.strip()
            mime = other.find(_q("MimeType", ADD))
            if mime is not None and mime.text:
                mime_type = mime.text.strip()
    return TslPointer(
        location=location.strip(), signer_certs=tuple(certs),
        territory=territory, tsl_type=tsl_type, mime_type=mime_type)


def _parse_provider(tsp: Element, territory: str | None) -> TrustServiceProvider:
    info = tsp.find(_q("TSPInformation"))
    name = _localized_name(info.find(_q("TSPName"))) if info is not None else None
    services: list[TrustServiceAnchor] = []
    svc_list = tsp.find(_q("TSPServices"))
    if svc_list is not None:
        for svc in svc_list.findall(_q("TSPService")):
            services.extend(_parse_service(svc, name, territory))
    return TrustServiceProvider(name=name, services=tuple(services))


def _parse_service(
    svc: Element, tsp_name: str | None, territory: str | None
) -> list[TrustServiceAnchor]:
    info = svc.find(_q("ServiceInformation"))
    if info is None:
        return []
    service_type = _text(info, _q("ServiceTypeIdentifier")) or ""
    service_status = _text(info, _q("ServiceStatus")) or ""
    service_name = _localized_name(info.find(_q("ServiceName")))
    certs = _certs_under(info.find(_q("ServiceDigitalIdentity")))
    return [
        TrustServiceAnchor(
            certificate=cert, service_type=service_type, service_status=service_status,
            tsp_name=tsp_name, service_name=service_name, territory=territory)
        for cert in certs
    ]


def _certs_under(node: Element | None) -> list[Any]:
    """Load every ``<X509Certificate>`` (base64 DER) beneath *node*, skipping any
    that will not load (a malformed cert never becomes a silent anchor)."""
    if node is None:
        return []
    from cryptography import x509
    out: list[Any] = []
    for el in node.iter(_q("X509Certificate")):
        if not el.text or not el.text.strip():
            continue
        try:
            out.append(x509.load_der_x509_certificate(base64.b64decode(el.text.strip())))
        except Exception:                      # a malformed cert is dropped, not trusted
            continue
    return out


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _text(parent: Element | None, tag: str) -> str | None:
    if parent is None:
        return None
    el = parent.find(tag)
    return el.text.strip() if el is not None and el.text else None


def _localized_name(name_parent: Element | None) -> str | None:
    """Pick a human name from a multilingual ``<Name xml:lang=..>`` list — English
    if present, else the first."""
    if name_parent is None:
        return None
    names = name_parent.findall(_q("Name"))
    for el in names:
        if el.get(XML_LANG, "").lower() == "en" and el.text:
            return el.text.strip()
    for el in names:
        if el.text:
            return el.text.strip()
    return None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _parse_datetime(value: str | None, ctx: str) -> datetime | None:
    """A TL date-time as a UTC ``datetime``, or ``None`` for a *null* value.

    ETSI TS 119 612 clause 5.1.3: every TL date-time is ISO 8601, expressed as
    **UTC**, with year, month, day, hour, minute, second and the ``Z`` designator —
    the shape :data:`_DATETIME_UTC` pins (a fraction of a second is tolerated and
    ``+00:00`` is accepted as the offset spelling of UTC, as the docs say; nothing
    else is). *value* is the stripped text of the ``<dateTime>`` element (``None`` /
    empty when the element is absent or empty — the null that clause 5.3.15 uses to
    mark a closed TL; the caller stages that).

    Anything else is :class:`TrustListParseError` — never ``None``, which the walk
    would read as unbounded validity (#389): another layout (the basic format, a
    non-``T`` separator, no seconds), another offset, a naive value — which is
    **not** read as UTC: a guessed zone would hand the expiry comparison an
    attacker-shaped instant, and it used to escape ``walk_lotl`` as a bare
    ``TypeError`` (#407) — or a field out of range (hour 24, 30 February). The shape
    and the fields are read by the regex, never by ``fromisoformat``, so the accept
    set is the same on every interpreter; the echoed value is cut by :func:`safe_repr`."""
    if not value:
        return None
    match = _DATETIME_UTC.fullmatch(value)
    if match is None:
        raise TrustListParseError(
            f"{ctx} dateTime {safe_repr(value)} is not a UTC date-time of the "
            f"YYYY-MM-DDThh:mm:ssZ form (ETSI TS 119 612 clause 5.1.3)")
    frac = match.group("frac") or ""
    try:
        return datetime(
            int(match["Y"]), int(match["m"]), int(match["d"]),
            int(match["H"]), int(match["M"]), int(match["S"]),
            int(frac[1:7].ljust(6, "0")) if frac else 0,      # truncated past six digits
            tzinfo=timezone.utc)
    except ValueError as exc:                   # a field out of range: hour 24, 30 February
        raise TrustListParseError(
            f"{ctx} dateTime {safe_repr(value)} is not a valid date-time "
            f"(ETSI TS 119 612 clause 5.1.3)") from exc


__all__ = ["parse_trust_list", "TSL", "ADD", "DEFAULT_MAX_BYTES"]
