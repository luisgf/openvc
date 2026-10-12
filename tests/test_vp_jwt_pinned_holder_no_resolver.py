"""
tests/test_vp_jwt_pinned_holder_no_resolver.py — ``VpJwtProofSuite.verify`` with a
pinned ``holder_key_jwk`` and no ``resolver``.

The resolver serves two things: the holder key (unless it is pinned) and the cascade
that verifies every embedded credential. Since 1.6.0 (#24) the cascade wraps it in
``batch_resolvers`` to dedupe resolution across the VP, but the resolver was only
defaulted when the holder key was NOT pinned. A pinned key with no resolver handed
``None`` to ``batch_resolvers`` and raised a bare ``AttributeError``, even for a VP
with no credentials, which escaped the ``OpenvcError`` contract.

The semantics pinned here: the resolver defaults to ``default_resolver()`` (as in
``verify_credential``) and serves the cascade only. The pinned key, never the
resolver, still decides the VP signature, and a cascade failure stays typed.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc.errors import OpenvcError
from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.errors import ClaimsInvalid, SignatureInvalid
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.verify import KeyResolutionFailed

V2 = "https://www.w3.org/ns/credentials/v2"
AUD, NONCE = "https://verifier.example", "chal-42"
# a holder the default resolver CANNOT resolve: if verify ever looked the holder
# key up instead of using the pinned one, these tests would fail
HOLDER = "did:example:holder"


def _did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did) — resolvable offline."""
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    mb = encode_multibase(bytes([0x80, 0x24]) + raw)       # multicodec p256-pub
    return P256SigningKey(priv, kid=f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _vc(issuer_key, issuer_did, subject=HOLDER):
    return VcJwtProofSuite().sign({
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer_did,
        "credentialSubject": {"id": subject, "role": "member"},
    }, signing_key=issuer_key)


def _holder():
    return Ed25519SigningKey.generate(kid=f"{HOLDER}#k")


def _present(credentials, holder_key):
    return VpJwtProofSuite().sign(
        credentials, holder_key=holder_key, audience=AUD, nonce=NONCE)


def test_empty_vp_with_pinned_key_and_no_resolver_verifies():
    # the reported repro: no credentials at all, yet it crashed in batch_resolvers
    hk = P256SigningKey.generate(kid="h")
    vp = _present([], hk)
    result = VpJwtProofSuite().verify(
        vp, audience=AUD, nonce=NONCE, holder_key_jwk=hk.public_jwk())
    assert result.credentials == ()
    assert result.holder == "h"


def test_did_key_credential_with_pinned_key_and_no_resolver_verifies():
    ik, issuer_did = _did_key_p256()
    hk = _holder()
    vp = _present([_vc(ik, issuer_did)], hk)
    result = VpJwtProofSuite().verify(
        vp, audience=AUD, nonce=NONCE, holder_key_jwk=hk.public_jwk())
    assert result.holder == HOLDER
    (cred,) = result.credentials
    assert cred.issuer == issuer_did            # resolved by the defaulted resolver
    assert cred.subject == HOLDER


def test_holder_binding_with_pinned_key_and_no_resolver():
    # the documented pinned-key binding path: expected_holder authenticates iss
    ik, issuer_did = _did_key_p256()
    hk = _holder()
    vp = _present([_vc(ik, issuer_did)], hk)
    result = VpJwtProofSuite().verify(
        vp, audience=AUD, nonce=NONCE, holder_key_jwk=hk.public_jwk(),
        expected_holder=HOLDER, require_holder_binding=True)
    assert result.holder == HOLDER

    # a credential issued to someone else still fails the binding
    vp = _present([_vc(ik, issuer_did, subject="did:example:someone-else")], hk)
    with pytest.raises(ClaimsInvalid, match="holder binding"):
        VpJwtProofSuite().verify(
            vp, audience=AUD, nonce=NONCE, holder_key_jwk=hk.public_jwk(),
            expected_holder=HOLDER, require_holder_binding=True)


def test_pinned_key_still_decides_the_signature():
    # the VP is signed by a did:key holder the default resolver CAN resolve from
    # iss/kid; the defaulted resolver must not rescue a pinned key that differs
    ik, issuer_did = _did_key_p256()
    signer, _ = _did_key_p256()
    vp = _present([_vc(ik, issuer_did)], signer)
    pinned = P256SigningKey.generate(kid="expected").public_jwk()
    with pytest.raises(SignatureInvalid):
        VpJwtProofSuite().verify(vp, audience=AUD, nonce=NONCE, holder_key_jwk=pinned)


def test_unresolvable_issuer_fails_typed():
    # the cascade's failure is an OpenvcError, so batch callers never abort
    hk = _holder()
    stray = P256SigningKey.generate(kid="did:example:issuer#k")
    vp = _present([_vc(stray, "did:example:issuer")], hk)
    with pytest.raises(KeyResolutionFailed) as exc:
        VpJwtProofSuite().verify(
            vp, audience=AUD, nonce=NONCE, holder_key_jwk=hk.public_jwk())
    assert isinstance(exc.value, OpenvcError)
