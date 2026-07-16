"""
openvc.trustlist.xades — a reference XAdES enveloped-signature verifier, behind the
``[trustlist]`` extra.

:func:`verify_xades_enveloped` is the fail-closed ``verify_signature`` callback that
:func:`openvc.trustlist.walk_lotl` / :func:`~openvc.trustlist.consume_trust_list`
need: it checks that a Trusted List's enveloped XML-DSig / XAdES signature verifies
against **one of** the expected signer certificates (the ones the parent list
vouched for). It wraps ``signxml`` (which sits on ``lxml`` + ``cryptography``), so
**core never imports it** — ``signxml`` is loaded lazily and only when this runs.

Security posture:

* **Trust is pinned.** The signature is verified against each *expected* certificate
  in turn (``signxml``'s ``x509_cert=``); an authentic-but-unexpected signer, a
  wrong key, or tampered content all fail. There is no fallback to whatever cert the
  document embeds.
* **Hardened input.** ``signxml`` forbids DTDs (XXE and entity-expansion are
  rejected outright), and the input is size-bounded before parsing.
* **Coverage is anchored on the enveloped ``URI=""`` reference, not a raw count.**
  Exactly one signed Reference must be the enveloped whole-document reference
  (``URI=""``) resolving to the document root — this is what defeats XML-Signature-
  Wrapping (``URI=""`` re-resolves to the current whole document, so a signed subtree
  moved under an attacker root of the same tag no longer matches). The only extras
  accepted are the References a XAdES-BASELINE signature legitimately carries — its
  own qualifying ``SignedProperties`` (the real EU LOTL and national TLs sign
  document + SignedProperties) and a co-signed ``ds:KeyInfo``; anything else fails
  closed.

This verifies the **cryptographic** authenticity of the enveloped signature (the
essential XML-DSig core of a TL's XAdES signature). Deeper XAdES qualifying-property
checks (the ``SigningCertificate`` property, signing time, policy) are a possible
future hardening; the caller may inject its own stricter ``verify_signature``.
"""
from __future__ import annotations

from typing import Any, Sequence

from .errors import TrustListSignatureBackendUnavailable, TrustListSignatureError
from .parse import DEFAULT_MAX_BYTES

_DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
# The qualifying-properties Reference every XAdES-BASELINE signature carries (EN 319 132-1;
# the 01903 v1.3.2 namespace is the one TS 119 612 trust lists use), and the optionally
# co-signed KeyInfo some XAdES producers add. Anything else stays rejected.
_XADES_SIGNED_PROPERTIES = "{http://uri.etsi.org/01903/v1.3.2#}SignedProperties"
_DS_KEY_INFO = f"{{{_DSIG_NS}}}KeyInfo"


def _reference_uris(signature_xml: Any) -> list[str | None]:
    """The ``URI`` of each ``ds:SignedInfo/ds:Reference``, in document order — the same
    order signxml returns its per-reference VerifyResults, so they align by index."""
    refs = signature_xml.findall(
        f"{{{_DSIG_NS}}}SignedInfo/{{{_DSIG_NS}}}Reference")
    return [r.get("URI") for r in refs]


def _check_signed_references(
    results: Sequence[Any], uris: Sequence[str | None], root_tag: str
) -> None:
    """Fail-closed structural check over the verified References (the XSW guard).

    Document coverage is anchored on the **enveloped whole-document reference**
    (``URI=""``): exactly one verified Reference must be it, and its resolved element
    must be the document root. This is what defeats XML-Signature-Wrapping — ``URI=""``
    re-resolves to *whatever* the whole document currently is, so a signed subtree
    relocated under an attacker-controlled root of the same tag (a by-``Id`` reference,
    ``URI="#x"``) no longer matches the digest. Checking the resolved element's *tag*
    alone is NOT enough: signxml resolves ``URI="#x"`` to the moved subtree, whose tag
    still equals ``root_tag`` — so tag-equality would accept the forgery. Beyond the
    document reference, the only References a XAdES-BASELINE signature legitimately
    carries are its own qualifying ``SignedProperties`` and a co-signed ``ds:KeyInfo``
    (same-document fragment references) — each at most once; anything else fails closed.
    """
    if len(uris) != len(results):
        raise TrustListSignatureError(
            "XAdES signature reference count does not match the verified results")
    doc_refs = 0
    for res, uri in zip(results, uris):
        signed = getattr(res, "signed_xml", None)
        tag = signed.tag if signed is not None else None
        if uri == "":                              # the enveloped whole-document reference
            if tag != root_tag:
                raise TrustListSignatureError(
                    "XAdES enveloped reference does not resolve to the trust list root")
            doc_refs += 1
        elif tag not in (_XADES_SIGNED_PROPERTIES, _DS_KEY_INFO):
            raise TrustListSignatureError(
                f"XAdES signature carries an unexpected signed reference (URI={uri!r}, "
                f"element {tag!r}): beyond the enveloped document only the XAdES "
                "SignedProperties and a co-signed ds:KeyInfo are accepted")
    if doc_refs != 1:
        raise TrustListSignatureError(
            "XAdES signature does not cover the whole trust list via a single enveloped "
            f"(URI='') reference (found {doc_refs}); possible XML signature wrapping")


def verify_xades_enveloped(
    xml: bytes,
    signer_certs: Sequence[Any],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> None:
    """Verify a Trusted List's enveloped XAdES / XML-DSig signature against
    *signer_certs*, returning ``None`` on success and raising on any failure — the
    exact shape :func:`openvc.trustlist.walk_lotl`'s ``verify_signature`` expects.

    The signature must verify against **one of** *signer_certs* (the certificates the
    parent list vouched for); each is tried in turn and the first that verifies wins.
    Accepted signature shapes: plain enveloped XML-DSig (one Reference over the
    document) and XAdES-BASELINE (document + the signature's own ``SignedProperties``,
    optionally a co-signed ``ds:KeyInfo``) — the shape real EU trusted lists carry.
    Raises :class:`TrustListSignatureError` on a bad/absent signature, tampered
    content, a DTD-bearing document, oversize input, unexpected signed references,
    or no matching signer; :class:`TrustListSignatureBackendUnavailable` if the
    ``[trustlist]`` extra (``signxml``) is not installed."""
    try:
        from cryptography.hazmat.primitives.serialization import Encoding
        from lxml import etree
        from signxml import (
            DigestAlgorithm,
            InvalidCertificate,
            InvalidDigest,
            InvalidInput,
            InvalidSignature,
            SignatureConfiguration,
            SignatureMethod,
            XMLVerifier,
        )
    except ImportError as exc:
        raise TrustListSignatureBackendUnavailable(
            "XAdES verification needs the trustlist extra: "
            "pip install openvc-core[trustlist]") from exc

    # Pin the XAdES-BASELINE-B algorithm profile: RSA / ECDSA (incl. RSA-PSS) over
    # SHA-256/384/512. This rejects HMAC, DSA, SHA-1/224 and SHA-3. The Reference COUNT is
    # deliberately not pinned here: every real XAdES-BASELINE signature carries the enveloped
    # document plus its own SignedProperties (the hard 1-reference pin shipped in v1.20.0
    # rejected the actual EU LOTL). Reference coverage is enforced structurally below in
    # _check_signed_references, which keeps the anti-wrapping posture.
    config = SignatureConfiguration(
        signature_methods=frozenset({
            SignatureMethod.RSA_SHA256, SignatureMethod.RSA_SHA384, SignatureMethod.RSA_SHA512,
            SignatureMethod.ECDSA_SHA256, SignatureMethod.ECDSA_SHA384,
            SignatureMethod.ECDSA_SHA512, SignatureMethod.SHA256_RSA_MGF1,
            SignatureMethod.SHA384_RSA_MGF1, SignatureMethod.SHA512_RSA_MGF1,
        }),
        digest_algorithms=frozenset({
            DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512}),
        expect_references=True,     # count/coverage enforced in _check_signed_references
    )

    if not isinstance(xml, (bytes, bytearray)):
        raise TrustListSignatureError(
            f"trust list must be bytes, got {type(xml).__name__}")
    if len(xml) > max_bytes:
        raise TrustListSignatureError(
            f"trust list is {len(xml)} bytes, over the {max_bytes}-byte cap")
    certs = list(signer_certs)
    if not certs:
        raise TrustListSignatureError("no expected signer certificates to verify against")

    data = bytes(xml)
    # The document root tag, parsed with entities/DTD/network off, to assert the signature
    # covers the WHOLE document (below) — signxml already rejects DTDs, this is defence in depth.
    try:
        root_tag = etree.fromstring(
            data, etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)).tag
    except etree.XMLSyntaxError as exc:
        raise TrustListSignatureError(f"trust list is not well-formed XML: {exc}") from exc

    signxml_errors = (InvalidSignature, InvalidCertificate, InvalidDigest, InvalidInput)
    last_err: Exception | None = None
    for cert in certs:
        try:
            pem = cert.public_bytes(Encoding.PEM).decode("ascii")
        except Exception as exc:               # not a usable x509.Certificate
            last_err = exc
            continue
        try:
            result = XMLVerifier().verify(data, x509_cert=pem, expect_config=config)
        except signxml_errors as exc:
            last_err = exc
            continue
        # XSW guard: the whole document must be signed via the enveloped URI="" reference
        # (so no signed subtree can be relocated under an attacker root while unsigned nodes
        # — extra TrustServiceProviders / certs — are consumed by the parser). Correlate each
        # verified reference with its SignedInfo URI (same order) and enforce that structurally.
        results = result if isinstance(result, list) else [result]
        uris = _reference_uris(results[0].signature_xml)
        _check_signed_references(results, uris, root_tag)
        return                                 # authentic + signed by a vouched cert + full scope
    raise TrustListSignatureError(
        f"trust list signature did not verify against any of the {len(certs)} "
        f"expected signer certificate(s): {last_err}")


__all__ = ["verify_xades_enveloped"]
