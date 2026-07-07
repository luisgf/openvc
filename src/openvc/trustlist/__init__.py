"""
openvc.trustlist — consume EU Trusted Lists (LOTL → national TL) as a verifier
X.509 trust-anchor source (eIDAS 2.0 / EUDI, ETSI TS 119 612).

A Trusted List is, for a verifier, a **source of EU-recognised X.509 anchors**.
:func:`walk_lotl` turns the Commission's List of Trusted Lists and the national
lists it points at into a :class:`TrustAnchorSet`; its ``.certificates`` feed the
existing X.509 path directly:

    from openvc import verify_credential
    from openvc.trustlist import walk_lotl
    from openvc.fetch import https_bytes_fetch

    anchors = walk_lotl(
        "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
        lotl_signer_certs=[commission_cert],     # caller-pinned root (no implicit trust)
        verify_signature=my_xades_verifier,      # injected, fail-closed
        fetch=https_bytes_fetch)
    verify_credential(vc, x5c_trust_anchors=anchors.certificates)

This adds no verification surface — :mod:`openvc.x5c` remains the path validator;
trust lists only tell it *which roots are EU-recognised*. Parsing is hardened
stdlib XML (no DTD/XXE, bounded); XML-signature verification is an **injected
callback** (the ``[trustlist]`` extra ships a reference XAdES one). See
``docs/adr/ADR-0003-eu-trusted-lists.md``.
"""
from __future__ import annotations

from .consume import (
    DEFAULT_SELECT,
    FetchTrustList,
    Select,
    ServiceStatus,
    ServiceType,
    VerifySignature,
    consume_trust_list,
    default_trust_list_fetch,
    walk_lotl,
)
from .errors import (
    TrustListError,
    TrustListParseError,
    TrustListSignatureBackendUnavailable,
    TrustListSignatureError,
    TrustListSignatureUnavailable,
)
from .model import (
    TrustAnchorSet,
    TrustList,
    TrustListProblem,
    TrustServiceAnchor,
    TrustServiceProvider,
    TslPointer,
)
from .parse import parse_trust_list
from .xades import verify_xades_enveloped

__all__ = [
    "DEFAULT_SELECT",
    "FetchTrustList",
    "Select",
    "ServiceStatus",
    "ServiceType",
    "TrustAnchorSet",
    "TrustList",
    "TrustListError",
    "TrustListParseError",
    "TrustListProblem",
    "TrustListSignatureBackendUnavailable",
    "TrustListSignatureError",
    "TrustListSignatureUnavailable",
    "TrustServiceAnchor",
    "TrustServiceProvider",
    "TslPointer",
    "VerifySignature",
    "consume_trust_list",
    "default_trust_list_fetch",
    "parse_trust_list",
    "verify_xades_enveloped",
    "walk_lotl",
]
