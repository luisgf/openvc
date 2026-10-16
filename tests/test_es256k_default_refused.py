"""
tests/test_es256k_default_refused.py — ES256K stays refused everywhere it was not asked for (#323).

``VcJwtProofSuite(allow_es256k=True)`` is the ONLY door (``test_es256k_opt_in.py``). This file
is the other half of that claim: with the default allow-list ``{ES256, ES384, EdDSA, Ed25519}``
no lane verifies ``ES256K``, ``allow_pq=True`` does not imply it, a caller-widened
``allowed_algs`` does not reach it, and the primitives have no secp256k1 branch to reach.

One parametrised sweep. Each case uses a REAL ES256K-signed token and the MATCHING secp256k1
public JWK, so a refusal cannot be blamed on a bad key (a control at the bottom verifies the
same token with the opt-in). An autouse spy records every call that reaches a signature
primitive (``openvc.keys.verify_signature`` wherever it is bound, PyJWT's decode) and fails the
sweep if ``ES256K`` ever got there: "before any crypto" is asserted, not assumed.

Hostile-input rule: every refusal below happens on a token whose issuer RESOLVES (a
``did:jwk`` carrying the secp256k1 key), so the class asserted is the lane's own refusal and
not an earlier ``KeyResolutionFailed``. Exact classes throughout.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import sys
import time
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

import jwt as pyjwt
import jwt.api_jws

from openvc import cbor, cose, keys as keys_module
from openvc.aio import verify_credential_async, verify_many_async
from openvc.did.base import DidResolutionError
from openvc.keys import InvalidKey, P256SigningKey, signing_key_from_jwk
from openvc.openid4vci import verify_credential_request_proofs
from openvc.proof import vc_jwt
from openvc.proof._jws import verify_compact
from openvc.proof.errors import (
    ClaimsInvalid,
    SignatureInvalid,
    UnsupportedAlgorithm,
)
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import ALLOWED_ALGS, VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.rp_registration import (
    RpRegistrationError,
    parse_rp_registration_certificate,
    verify_rp_registration_certificate,
)
from openvc.status.issue import verify_status_list_token
from openvc.trustlist.errors import TrustListSignatureError
from openvc.trustlist.lote import consume_lote
from openvc.verify import verify_credential, verify_many

# --------------------------------------------------------------------------- #
# Helpers (copied: tests/ is not a package)
# --------------------------------------------------------------------------- #

NOW = int(time.time())
KEY = ec.generate_private_key(ec.SECP256K1())
_NUMS = KEY.public_key().public_numbers()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


JWK = {"kty": "EC", "crv": "secp256k1",
       "x": b64(_NUMS.x.to_bytes(32, "big")), "y": b64(_NUMS.y.to_bytes(32, "big"))}
ISSUER = "did:jwk:" + b64(json.dumps(JWK, separators=(",", ":")).encode())     # resolvable
KID = ISSUER + "#0"
PROOF_ISSUER = "https://issuer.example"


def es256k_jws(payload: dict[str, Any], *, header: dict[str, Any] | None = None) -> str:
    """A compact JWS signed ES256K by KEY, raw R||S."""
    head = {"alg": "ES256K", "typ": "JWT", "kid": KID}
    head.update(header or {})
    h, p = b64(json.dumps(head).encode()), b64(json.dumps(payload).encode())
    r, s = decode_dss_signature(KEY.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{h}.{p}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def vc_payload() -> dict[str, Any]:
    return {"iss": ISSUER, "nbf": NOW - 5, "iat": NOW - 5, "exp": NOW + 3600,
            "vc": {"@context": ["https://www.w3.org/2018/credentials/v1"],
                   "type": ["VerifiableCredential"], "issuer": ISSUER,
                   "credentialSubject": {"id": "did:example:subject"}}}


VC_JWT = es256k_jws(vc_payload())


@pytest.fixture(autouse=True)
def crypto_spy(monkeypatch):
    """Record the algorithm of every signature check that is reached, wherever it is bound."""
    seen: list[str] = []
    original = keys_module.verify_signature

    def spy_primitive(*, alg, public_jwk, signing_input, signature):
        seen.append(alg)
        return original(alg=alg, public_jwk=public_jwk, signing_input=signing_input,
                        signature=signature)

    for module in list(sys.modules.values()):
        if getattr(module, "verify_signature", None) is original:
            monkeypatch.setattr(module, "verify_signature", spy_primitive)

    real_decode = pyjwt.PyJWT.decode_complete
    real_jws = jwt.api_jws.PyJWS.decode_complete

    def header_alg(token: Any) -> str:
        try:
            head = json.loads(base64.urlsafe_b64decode(str(token).split(".")[0] + "=="))
            return str(head.get("alg"))
        except Exception:
            return "?"

    def spy_jwt(self, jwt_, *a, **k):
        seen.append("pyjwt:" + header_alg(jwt_))
        return real_decode(self, jwt_, *a, **k)

    def spy_jws(self, jwt_, *a, **k):
        seen.append("pyjwt:" + header_alg(jwt_))
        return real_jws(self, jwt_, *a, **k)

    monkeypatch.setattr(pyjwt.PyJWT, "decode_complete", spy_jwt)
    monkeypatch.setattr(jwt.api_jws.PyJWS, "decode_complete", spy_jws)
    yield seen
    assert not any(entry.endswith("ES256K") for entry in seen), seen


def refuses(call: Callable[[], Any], exc_class: type[Exception], seen: list[str], *,
            match: str | None = None) -> None:
    """The call raises EXACTLY *exc_class* and no signature check was reached."""
    with pytest.raises(exc_class, match=match) as excinfo:
        call()
    assert type(excinfo.value) is exc_class, type(excinfo.value)
    assert seen == [], f"a signature check ran before the refusal: {seen}"


# --------------------------------------------------------------------------- #
# The constants and the primitives
# --------------------------------------------------------------------------- #

def test_the_default_allow_list_is_the_four_names_and_es256k_is_a_separate_set():
    assert ALLOWED_ALGS == frozenset({"ES256", "ES384", "EdDSA", "Ed25519"})
    assert vc_jwt.ALLOWED_ALGS_ES256K == frozenset({"ES256K"})
    assert vc_jwt.ALLOWED_ALGS_ES256K.isdisjoint(ALLOWED_ALGS)
    assert "ES256K" not in ALLOWED_ALGS | vc_jwt.ALLOWED_ALGS_PQ


def test_the_signature_primitive_has_no_secp256k1_branch(crypto_spy):
    # the second gate every other lane keeps: even a widened allow-list cannot reach a
    # verifier, because openvc.keys.verify_signature raises for the name
    with pytest.raises(InvalidKey, match="unsupported alg 'ES256K'") as exc:
        keys_module.verify_signature(alg="ES256K", public_jwk=JWK, signing_input=b"x",
                                     signature=bytes(64))
    assert type(exc.value) is InvalidKey
    assert crypto_spy == ["ES256K"]
    crypto_spy.clear()                      # this test calls the primitive on purpose


def test_a_secp256k1_private_jwk_has_no_signing_backend():
    private = dict(JWK, d=b64(KEY.private_numbers().private_value.to_bytes(32, "big")))
    with pytest.raises(InvalidKey, match="unsupported key type") as exc:
        signing_key_from_jwk(private, "k")
    assert type(exc.value) is InvalidKey


def test_no_secp256k1_signing_key_class_exists():
    assert not any("256k1" in name or "K1" in name for name in keys_module.__all__)
    assert not hasattr(keys_module, "Secp256k1SigningKey")


def test_cose_has_no_es256k_mapping():
    assert -47 not in cose.COSE_ALG_TO_JOSE                # RFC 8812's COSE value for ES256K
    assert "ES256K" not in cose.COSE_ALG_TO_JOSE.values()


# --------------------------------------------------------------------------- #
# The sweep: one real ES256K token per lane, default configuration
# --------------------------------------------------------------------------- #

def _sd_jwt_with_es256k_issuer() -> str:
    payload = {"iss": ISSUER, "vct": "https://credentials.example/id", "iat": NOW - 5,
               "exp": NOW + 3600, "_sd_alg": "sha-256"}
    return es256k_jws(payload, header={"typ": "dc+sd-jwt"}) + "~"


def _sd_jwt_with_es256k_kb() -> tuple[str, str, str]:
    """An SD-JWT whose ISSUER JWT is a genuine ES256 one (so the allow-listed first stage
    passes) binding a secp256k1 holder key, plus a KB-JWT signed ES256K by that holder."""
    issuer = P256SigningKey.generate(kid="did:example:issuer#k")
    issued = SdJwtVcProofSuite().issue(
        {"iss": "did:example:issuer"}, signing_key=issuer, vct="https://credentials.example/id",
        holder_jwk=JWK)
    presented = issued if issued.endswith("~") else issued + "~"
    import hashlib
    sd_hash = b64(hashlib.sha256(presented.encode("ascii")).digest())
    kb = es256k_jws({"aud": "https://rp.example", "nonce": "n-1", "iat": NOW,
                     "sd_hash": sd_hash}, header={"typ": "kb+jwt", "kid": None})
    return presented + kb, "https://rp.example", json.dumps(issuer.public_jwk())


def _vp_jwt() -> str:
    return es256k_jws({"iss": ISSUER, "aud": "https://rp.example", "nonce": "n-1",
                       "iat": NOW - 5, "exp": NOW + 3600,
                       "vp": {"type": ["VerifiablePresentation"], "holder": ISSUER}})


def _status_token() -> str:
    return es256k_jws({"sub": "https://status.example/1", "iat": NOW - 5, "exp": NOW + 3600,
                       "status_list": {"bits": 1, "lst": "eNpjAAAAAQAB"}},
                      header={"typ": "statuslist+jwt"})


def _key_proof(allowed: frozenset[str] | None) -> Callable[[], Any]:
    proof = es256k_jws(
        {"aud": PROOF_ISSUER, "iat": NOW - 5, "nonce": "c-nonce"},
        header={"typ": "openid4vci-proof+jwt", "kid": None, "jwk": JWK})
    kwargs: dict[str, Any] = {} if allowed is None else {"allowed_algs": allowed}
    return lambda: verify_credential_request_proofs(
        {"credential_configuration_id": "cfg", "proofs": {"jwt": [proof]}},
        credential_issuer=PROOF_ISSUER,
        check_nonce=lambda n: True, now=dt.datetime.fromtimestamp(NOW, dt.timezone.utc),
        **kwargs)


def _self_signed(key: ec.EllipticCurvePrivateKey | None = None) -> x509.Certificate:
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "registrar")])
    now = dt.datetime.fromtimestamp(NOW, dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))


def _wrprc() -> str:
    cert = _self_signed()
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return es256k_jws({"sub": "x"}, header={"typ": "rc-wrp+jwt", "kid": None, "x5c": [x5c]})


def _lote() -> tuple[str, x509.Certificate]:
    """A LoTE-shaped JWS signed ES256K by KEY, whose x5c carries a certificate for KEY."""
    cert = _self_signed(KEY)
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return es256k_jws({"LoTE": {}}, header={"kid": None, "x5c": [x5c]}), cert


def _cose_es256k() -> cose.CoseSign1:
    protected = cbor.encode({1: -47})                        # alg = ES256K (-47)
    return cose.parse_sign1([protected, {}, b"payload", bytes(64)])


SWEEP: list[tuple[str, Callable[[], Callable[[], Any]], type[Exception], str | None]] = [
    # (id, a factory of the call, the exact class the lane refuses with, a message fragment)
    ("vc-jwt default", lambda: lambda: VcJwtProofSuite().verify(
        VC_JWT, public_key_jwk=JWK), UnsupportedAlgorithm, "'ES256K' is not permitted"),
    ("vc-jwt allow_pq", lambda: lambda: VcJwtProofSuite(allow_pq=True).verify(
        VC_JWT, public_key_jwk=JWK), UnsupportedAlgorithm, "'ES256K' is not permitted"),
    ("sd-jwt issuer jwt", lambda: lambda: SdJwtVcProofSuite().verify(
        _sd_jwt_with_es256k_issuer(), public_key_jwk=JWK), UnsupportedAlgorithm,
     "'ES256K' is not permitted"),
    ("sd-jwt issuer jwt allow_pq", lambda: lambda: SdJwtVcProofSuite(allow_pq=True).verify(
        _sd_jwt_with_es256k_issuer(), public_key_jwk=JWK), UnsupportedAlgorithm,
     "'ES256K' is not permitted"),
    ("vp-jwt", lambda: lambda: VpJwtProofSuite().verify(
        _vp_jwt(), audience="https://rp.example", nonce="n-1", holder_key_jwk=JWK),
     UnsupportedAlgorithm, "'ES256K' is not permitted"),
    ("verify_compact default", lambda: lambda: verify_compact(
        VC_JWT, public_key_jwk=JWK), UnsupportedAlgorithm, "'ES256K' is not permitted"),
    ("status-list token", lambda: lambda: verify_status_list_token(
        _status_token(), public_key_jwk=JWK, expected_uri="https://status.example/1"),
     UnsupportedAlgorithm, "'ES256K' is not permitted"),
    ("openid4vci key proof", lambda: _key_proof(None), UnsupportedAlgorithm, "not allow-listed"),
    ("openid4vci key proof, allowed_algs widened", lambda: _key_proof(
        ALLOWED_ALGS | {"ES256K"}), UnsupportedAlgorithm, "no key binding rule"),
    ("wrprc jwt (parse)", lambda: lambda: parse_rp_registration_certificate(_wrprc()),
     RpRegistrationError, "not permitted"),
    ("wrprc jwt (verify)", lambda: lambda: verify_rp_registration_certificate(
        _wrprc(), trust_anchors=[_self_signed()]), RpRegistrationError, "not permitted"),
    ("lote", lambda: lambda: consume_lote(
        _lote()[0], expected_signer_certs=[_lote()[1]]), TrustListSignatureError,
     "not permitted"),
    ("cose sign1 alg -47", lambda: lambda: cose.verify_sign1(_cose_es256k(), public_jwk=JWK),
     cose.CoseUnsupportedAlgorithm, "not allow-listed"),
    ("verify_credential", lambda: lambda: verify_credential(VC_JWT),
     UnsupportedAlgorithm, "'ES256K' is not permitted"),
    ("verify_credential_async", lambda: lambda: asyncio.run(verify_credential_async(VC_JWT)),
     UnsupportedAlgorithm, "'ES256K' is not permitted"),
]


@pytest.mark.parametrize("name,factory,exc_class,fragment", SWEEP, ids=[s[0] for s in SWEEP])
def test_every_lane_refuses_es256k_by_default_before_any_crypto(
        name, factory, exc_class, fragment, crypto_spy):
    refuses(factory(), exc_class, crypto_spy, match=fragment)


def test_verify_compact_with_a_widened_allow_list_is_refused_by_the_primitive(crypto_spy):
    # naming ES256K in allowed_algs gets past the first gate and stops at the second: the
    # primitive has no branch for it (SignatureInvalid wrapping the InvalidKey)
    with pytest.raises(SignatureInvalid, match="unsupported alg 'ES256K'") as exc:
        verify_compact(VC_JWT, public_key_jwk=JWK, allowed_algs=ALLOWED_ALGS | {"ES256K"})
    assert type(exc.value) is SignatureInvalid
    assert crypto_spy == ["ES256K"]
    crypto_spy.clear()                      # the one case allowed to reach the primitive


def test_a_widened_allow_list_cannot_make_the_sd_jwt_suite_verify_es256k(crypto_spy):
    # SdJwtVcProofSuite has no allowed_algs parameter and no allow_es256k keyword
    with pytest.raises(TypeError):
        SdJwtVcProofSuite(allow_es256k=True)                # type: ignore[call-arg]
    with pytest.raises(TypeError):
        VpJwtProofSuite(allow_es256k=True)                  # type: ignore[call-arg]


def test_the_sd_jwt_key_binding_jwt_is_refused_after_the_issuer_jwt_only(crypto_spy):
    presentation, audience, issuer_jwk = _sd_jwt_with_es256k_kb()
    with pytest.raises(UnsupportedAlgorithm, match="KB-JWT algorithm 'ES256K'") as exc:
        SdJwtVcProofSuite().verify(
            presentation, public_key_jwk=json.loads(issuer_jwk), audience=audience,
            nonce="n-1", require_key_binding=True)
    assert type(exc.value) is UnsupportedAlgorithm
    # the ES256 issuer JWT was checked (the lane worked), the ES256K KB-JWT never was
    assert crypto_spy == ["ES256"]
    crypto_spy.clear()


def test_the_sd_jwt_suite_with_allow_pq_still_refuses_an_es256k_key_binding_jwt(crypto_spy):
    presentation, audience, issuer_jwk = _sd_jwt_with_es256k_kb()
    with pytest.raises(UnsupportedAlgorithm, match="KB-JWT algorithm 'ES256K'") as exc:
        SdJwtVcProofSuite(allow_pq=True).verify(
            presentation, public_key_jwk=json.loads(issuer_jwk), audience=audience,
            nonce="n-1", require_key_binding=True)
    assert type(exc.value) is UnsupportedAlgorithm
    assert crypto_spy == ["ES256"]
    crypto_spy.clear()


def test_the_sd_jwt_suite_does_not_sign_es256k():
    class Stub:
        alg, kid = "ES256K", "k"

        def sign(self, signing_input: bytes) -> bytes:       # pragma: no cover - must not run
            raise AssertionError("signed")

    with pytest.raises(UnsupportedAlgorithm):
        SdJwtVcProofSuite().issue({"iss": "did:example:i"}, signing_key=Stub(),
                                  vct="https://credentials.example/id")


# --------------------------------------------------------------------------- #
# The pipelines: verify_many and its async twin isolate the item, same class
# --------------------------------------------------------------------------- #

def test_verify_many_reports_the_refusal_per_item_and_keeps_going(crypto_spy):
    good_issuer = P256SigningKey.generate(kid="did:example:g#k")          # not resolvable
    results = verify_many([VC_JWT, "not-a-token", VC_JWT])
    assert [r.index for r in results] == [0, 1, 2]
    assert type(results[0].error) is UnsupportedAlgorithm
    assert type(results[2].error) is UnsupportedAlgorithm
    assert results[1].error is not None and results[1].result is None
    assert good_issuer is not None and crypto_spy == []


def test_verify_many_async_reports_the_refusal_per_item(crypto_spy):
    results = asyncio.run(verify_many_async([VC_JWT, VC_JWT]))
    assert [type(r.error) for r in results] == [UnsupportedAlgorithm, UnsupportedAlgorithm]
    assert crypto_spy == []


def test_the_issuer_in_the_sweep_really_resolves(crypto_spy):
    # the control for "a refusal cannot be blamed on resolution": the did:jwk resolves to the
    # very key that signed the token, and the opt-in verifies the same bytes
    from openvc.verify import default_resolver
    doc = default_resolver().resolve(ISSUER)
    assert doc.key_by_kid(KID).public_key_jwk == JWK
    assert VcJwtProofSuite(allow_es256k=True).verify(VC_JWT, public_key_jwk=JWK).issuer == ISSUER
    assert set(crypto_spy) == {"pyjwt:ES256K"}   # the opt-in is the one lane that reaches PyJWT
    crypto_spy.clear()


def test_did_key_for_secp256k1_stays_unsupported():
    # multicodec secp256k1-pub (0xe7 0x01) + a compressed point: `multikey_to_jwk` is P-256 /
    # P-384 only, and this issue does not change that (it is listed as out of scope)
    from openvc.multibase import encode_multibase
    from openvc.verify import default_resolver
    compressed = KEY.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    did = "did:key:" + encode_multibase(bytes([0xE7, 0x01]) + compressed)
    with pytest.raises(DidResolutionError) as exc:
        default_resolver().resolve(did)
    assert type(exc.value) is DidResolutionError
    # the expected-class control: an invalid-claims error is NOT what this is
    assert not isinstance(exc.value, ClaimsInvalid)
