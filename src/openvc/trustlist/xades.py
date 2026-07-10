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

This verifies the **cryptographic** authenticity of the enveloped signature (the
essential XML-DSig core of a TL's XAdES signature). Deeper XAdES qualifying-property
checks (the ``SigningCertificate`` property, signing time, policy) are a possible
future hardening; the caller may inject its own stricter ``verify_signature``.
"""
from __future__ import annotations

from typing import Any, Sequence

from .errors import TrustListSignatureBackendUnavailable, TrustListSignatureError
from .parse import DEFAULT_MAX_BYTES


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
    Raises :class:`TrustListSignatureError` on a bad/absent signature, tampered
    content, a DTD-bearing document, oversize input, or no matching signer;
    :class:`TrustListSignatureBackendUnavailable` if the ``[trustlist]`` extra
    (``signxml``) is not installed."""
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
    # SHA-256/384/512, exactly one Reference. This rejects HMAC, DSA, SHA-1/224 and SHA-3,
    # and — with expect_references=1 — a second Reference smuggling in a wrapped fragment.
    config = SignatureConfiguration(
        signature_methods=frozenset({
            SignatureMethod.RSA_SHA256, SignatureMethod.RSA_SHA384, SignatureMethod.RSA_SHA512,
            SignatureMethod.ECDSA_SHA256, SignatureMethod.ECDSA_SHA384,
            SignatureMethod.ECDSA_SHA512, SignatureMethod.SHA256_RSA_MGF1,
            SignatureMethod.SHA384_RSA_MGF1, SignatureMethod.SHA512_RSA_MGF1,
        }),
        digest_algorithms=frozenset({
            DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512}),
        expect_references=1,
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
        # XSW guard: consume signxml's verified subtree — it MUST be the document root, so a
        # single valid Reference cannot cover only a fragment while unsigned nodes (extra
        # TrustServiceProviders / certs) are wrapped outside the signed scope and later parsed.
        if isinstance(result, list):               # expect_references=1 should preclude this
            if len(result) != 1:
                raise TrustListSignatureError(
                    f"expected exactly one signed reference, got {len(result)}")
            result = result[0]
        signed = result.signed_xml
        if signed is None or signed.tag != root_tag:
            raise TrustListSignatureError(
                "XAdES signature does not cover the whole trust list (XML signature wrapping)")
        return                                 # authentic + signed by a vouched cert + full scope
    raise TrustListSignatureError(
        f"trust list signature did not verify against any of the {len(certs)} "
        f"expected signer certificate(s): {last_err}")


__all__ = ["verify_xades_enveloped"]
