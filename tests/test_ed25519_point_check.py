"""Ed25519 public keys of small order or non-canonical encoding are refused everywhere a
key is built for verification (issue #429, security review of 2026-11-17).

`Ed25519PublicKey.from_public_bytes` checks only the length. Under the identity point, the
signature `R = identity, S = 0` verifies for every message, so a credential "signed" by such
a key needs no private key at all, and the identity has four spellings (distinct thumbprints).
`keys.canonical_public_jwk` already refused these (#379), on the OpenID4VCI lane only; the rule
is now `keys.check_ed25519_point`, applied by `keys.verify_signature` (SD-JWT issuer JWT and
KB-JWT, VP-JWT, status tokens, the JCS suites, did:webvh, COSE, LoTE, WRPRC), by the VC-JWT
PyJWT lane and by `eddsa-rdfc-2022`.

Every hostile case is paired with a control: a valid key under the same forged signature is
`SignatureInvalid`, so a refusal can only come from the point check, and a genuinely signed
artefact under a valid key still verifies. Each lane keeps its own error family, pinned by
exact class (`type(exc) is ...`). Self-contained (tests/ is not a package).
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone

import pytest

from openvc import VerificationPolicy, verify_credential, verify_many
from openvc.did.did_webvh import (
    DidWebvhError,
    DidWebvhResolver,
    _multihash_b58,
    _jcs,
)
from openvc.errors import OpenvcError
from openvc.keys import (
    Ed25519SigningKey,
    InvalidKey,
    verify_signature,
)
from openvc.multibase import encode_multibase
from openvc.proof._jws import sign_compact, verify_compact
from openvc.proof.data_integrity import DataIntegrityProofSuite
from openvc.proof.di_jcs import EddsaJcsProofSuite
from openvc.proof.errors import ProofError, ProofMalformed, SignatureInvalid
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status.issue import build_status_list_token, verify_status_list_token

V2 = "https://www.w3.org/ns/credentials/v2"
NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)

P = 2**255 - 19
_ORDER8_Y = 2707385501144840649318225287225658788936804267575313519463743609750303402022

# the six hostile 32-byte encodings: the identity, the point of order 2, an order-4 point,
# an order-8 point, the identity spelled with y = 1 + p, and y = p itself (also >= p)
POINTS = {
    "identity": bytes([1]) + bytes(31),
    "order2": bytes([0xEC]) + bytes([0xFF] * 30) + bytes([0x7F]),
    "order4": bytes(32),
    "order8": _ORDER8_Y.to_bytes(32, "little"),
    "noncanonical-identity": bytes([0xEE]) + bytes([0xFF] * 30) + bytes([0x7F]),
    "y-equals-p": bytes([0xED]) + bytes([0xFF] * 30) + bytes([0x7F]),
}
POINT_IDS = list(POINTS)
FORGED_SIG = bytes([1]) + bytes(31) + bytes(32)         # R = identity, S = 0


def _unusable():
    """The refusal's class, imported late so the rest of the file collects on a tree
    that predates it (the behavioural tests must fail on their merits there)."""
    from openvc.keys import UnusablePublicKey

    return UnusablePublicKey


def _says_point(exc: BaseException) -> bool:
    """True when the refusal text is the point check's (so a refusal that merely happens to
    fail on the forged signature, which depends on the payload, can never satisfy it)."""
    return "small-order" in str(exc) or "canonical" in str(exc)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(raw: bytes) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}


def _did_jwk(raw: bytes) -> str:
    return "did:jwk:" + _b64u(json.dumps(_jwk(raw), separators=(",", ":"), sort_keys=True).encode())


def _did_key(raw: bytes) -> str:
    return "did:key:" + encode_multibase(bytes([0xED, 0x01]) + raw)


def _valid_raw() -> bytes:
    return Ed25519SigningKey.generate(kid="k").public_key_raw()


def _forged_jws(header: dict, payload: dict) -> str:
    return (_b64u(json.dumps(header).encode()) + "." + _b64u(json.dumps(payload).encode())
            + "." + _b64u(FORGED_SIG))


def _forged_vc_jwt(did: str, jti: str = "urn:uuid:1") -> str:
    now = int(time.time())
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:victim"}}
    frag = did[len("did:key:"):] if did.startswith("did:key:") else "0"
    return _forged_jws({"alg": "EdDSA", "typ": "JWT", "kid": f"{did}#{frag}"},
                       {"iss": did, "sub": "did:example:victim", "nbf": now, "iat": now,
                        "jti": jti, "vc": vc})


# ------------------------------------------------------------- the helper itself #

@pytest.mark.parametrize("name", POINT_IDS)
def test_helper_refuses_every_hostile_encoding(name):
    from openvc.keys import check_ed25519_point      # inside: the rest must collect on main
    with pytest.raises(InvalidKey) as info:
        check_ed25519_point(POINTS[name])
    assert type(info.value) is _unusable()


def test_helper_accepts_a_real_key():
    from openvc.keys import check_ed25519_point
    check_ed25519_point(_valid_raw())


# ------------------------------------------------------------- keys.verify_signature #

@pytest.mark.parametrize("alg", ["EdDSA", "Ed25519"])
@pytest.mark.parametrize("name", POINT_IDS)
def test_verify_signature_refuses_typed_never_false(name, alg):
    with pytest.raises(InvalidKey) as info:
        verify_signature(alg=alg, public_jwk=_jwk(POINTS[name]),
                         signing_input=b"anything", signature=FORGED_SIG)
    assert type(info.value) is _unusable()
    # not re-wrapped into the generic "malformed public key" message of the wrapper
    assert "malformed public key" not in str(info.value)


def test_verify_signature_control_valid_key():
    key = Ed25519SigningKey.generate(kid="k")
    jwk = _jwk(key.public_key_raw())
    assert verify_signature(alg="EdDSA", public_jwk=jwk, signing_input=b"m",
                            signature=key.sign(b"m")) is True
    # the same forged signature under a valid key is a plain False, not a key refusal
    assert verify_signature(alg="EdDSA", public_jwk=jwk, signing_input=b"m",
                            signature=FORGED_SIG) is False


def test_verify_signature_bad_length_keeps_its_message():
    with pytest.raises(InvalidKey, match="malformed public key"):
        verify_signature(alg="EdDSA", public_jwk=_jwk(bytes(31)),
                         signing_input=b"m", signature=FORGED_SIG)


# ----------------------------------------------------- VC-JWT (PyJWT lane) end to end #

@pytest.mark.parametrize("make_did", [_did_jwk, _did_key], ids=["did-jwk", "did-key"])
@pytest.mark.parametrize("name", POINT_IDS)
def test_vc_jwt_refuses_through_verify_credential(name, make_did):
    did = make_did(POINTS[name])
    token = _forged_vc_jwt(did)
    with pytest.raises(ProofError) as info:
        verify_credential(token)
    assert type(info.value) is SignatureInvalid
    assert "small-order" in str(info.value) or "canonical" in str(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_vc_jwt_suite_refuses_a_pinned_key(name):
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite().verify(_forged_vc_jwt("did:example:x"),
                                 public_key_jwk=_jwk(POINTS[name]))
    assert type(info.value) is SignatureInvalid
    assert _says_point(info.value)


def test_vc_jwt_control_valid_key_same_forged_signature():
    did = _did_jwk(_valid_raw())
    with pytest.raises(SignatureInvalid):
        verify_credential(_forged_vc_jwt(did))


def _genuine_token() -> str:
    key = Ed25519SigningKey.generate(kid="k")
    did = _did_jwk(key.public_key_raw())
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:holder"}}
    return VcJwtProofSuite().sign(
        vc, signing_key=_KeyAt(key, f"{did}#0"))


class _KeyAt:
    """The same key under a different kid (the kid is what names the verification method)."""

    def __init__(self, key, kid):
        self._key, self.kid, self.alg = key, kid, key.alg

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


def test_vc_jwt_control_genuine_credential_verifies():
    assert verify_credential(_genuine_token()).issuer.startswith("did:jwk:")


def test_verify_many_returns_a_per_item_error():
    items = [_forged_vc_jwt(_did_jwk(POINTS["identity"])), _genuine_token(),
             _forged_vc_jwt(_did_key(POINTS["order2"]), jti="urn:uuid:2")]
    out = verify_many(items, policy=VerificationPolicy())
    assert [r.ok for r in out] == [False, True, False]
    for r in (out[0], out[2]):
        assert isinstance(r.error, OpenvcError)
        assert type(r.error) is SignatureInvalid


def test_vc_jwt_wrong_length_x_keeps_its_class():
    """Rule C: a bad key that is not the new refusal keeps the class it had."""
    did = _did_jwk(bytes(31))
    with pytest.raises(ProofError) as info:
        verify_credential(_forged_vc_jwt(did))
    assert type(info.value) is ProofError
    assert "could not load EdDSA key from JWK" in str(info.value)


# ------------------------------------------------------ SD-JWT VC issuer JWT and KB-JWT #

def _sd_jwt_with_forged_issuer_signature() -> str:
    head = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    body = {"iss": "https://issuer.example", "vct": "https://example.com/vct",
            "iat": int(time.time()), "_sd_alg": "sha-256"}
    return _forged_jws(head, body) + "~"


@pytest.mark.parametrize("name", POINT_IDS)
def test_sd_jwt_issuer_jwt_refuses(name):
    with pytest.raises(ProofError) as info:
        SdJwtVcProofSuite().verify(_sd_jwt_with_forged_issuer_signature(),
                                   public_key_jwk=_jwk(POINTS[name]))
    assert type(info.value) is SignatureInvalid
    assert "could not verify" in str(info.value)


def test_sd_jwt_issuer_jwt_control():
    with pytest.raises(SignatureInvalid):
        SdJwtVcProofSuite().verify(_sd_jwt_with_forged_issuer_signature(),
                                   public_key_jwk=_jwk(_valid_raw()))


def _sd_jwt_bound_to(holder_x: bytes, issuer: Ed25519SigningKey) -> str:
    """An issuer-signed SD-JWT whose cnf.jwk is *holder_x* (an issuer other than openvc may
    bind any key), followed by a KB-JWT signed by nobody (the forged signature)."""
    now = int(time.time())
    body = {"iss": "https://issuer.example", "vct": "https://example.com/vct", "iat": now,
            "_sd_alg": "sha-256", "cnf": {"jwk": _jwk(holder_x)}}
    issuer_jwt = sign_compact({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": issuer.kid},
                              body, signing_key=issuer)
    kb = _forged_jws({"alg": "EdDSA", "typ": "kb+jwt"},
                     {"aud": "https://verifier.example", "nonce": "n-1", "iat": now,
                      "sd_hash": "x"})
    return issuer_jwt + "~" + kb


@pytest.mark.parametrize("name", POINT_IDS)
def test_kb_jwt_under_a_small_order_cnf_jwk_refuses(name):
    issuer = Ed25519SigningKey.generate(kid="i")
    ipub = _jwk(issuer.public_key_raw())
    with pytest.raises(ProofError) as info:
        SdJwtVcProofSuite().verify(
            _sd_jwt_bound_to(POINTS[name], issuer), public_key_jwk=ipub,
            audience="https://verifier.example", nonce="n-1", require_key_binding=True)
    assert type(info.value) is SignatureInvalid
    assert "KB-JWT" in str(info.value)
    assert _says_point(info.value)


def test_sd_jwt_wrong_length_x_keeps_its_class():
    with pytest.raises(ProofError) as info:
        SdJwtVcProofSuite().verify(_sd_jwt_with_forged_issuer_signature(),
                                   public_key_jwk=_jwk(bytes(31)))
    assert type(info.value) is ProofError
    assert "could not verify" in str(info.value)


def test_kb_jwt_wrong_length_cnf_x_keeps_its_class():
    issuer = Ed25519SigningKey.generate(kid="i")
    with pytest.raises(ProofError) as info:
        SdJwtVcProofSuite().verify(
            _sd_jwt_bound_to(bytes(31), issuer),
            public_key_jwk=_jwk(issuer.public_key_raw()),
            audience="https://verifier.example", nonce="n-1", require_key_binding=True)
    assert type(info.value) is ProofError
    assert "KB-JWT" in str(info.value)


def test_kb_jwt_control_valid_cnf_key_same_forged_signature():
    issuer = Ed25519SigningKey.generate(kid="i")
    with pytest.raises(SignatureInvalid):
        SdJwtVcProofSuite().verify(
            _sd_jwt_bound_to(_valid_raw(), issuer),
            public_key_jwk=_jwk(issuer.public_key_raw()),
            audience="https://verifier.example", nonce="n-1", require_key_binding=True)


# ------------------------------------------------- VP-JWT / status token (verify_compact) #

@pytest.mark.parametrize("name", POINT_IDS)
def test_verify_compact_refuses(name):
    token = _forged_jws({"alg": "EdDSA"}, {"a": 1})
    with pytest.raises(SignatureInvalid) as info:
        verify_compact(token, public_key_jwk=_jwk(POINTS[name]))
    assert type(info.value) is SignatureInvalid
    assert "could not verify" in str(info.value)


def test_verify_compact_control():
    token = _forged_jws({"alg": "EdDSA"}, {"a": 1})
    with pytest.raises(SignatureInvalid, match="verification failed"):
        verify_compact(token, public_key_jwk=_jwk(_valid_raw()))


@pytest.mark.parametrize("name", POINT_IDS)
def test_status_list_token_refuses(name):
    from openvc.status.bitstring import StatusListError
    from openvc.status.token_status_list import new_status_list

    signer = Ed25519SigningKey.generate(kid="s")
    token = build_status_list_token(signing_key=signer, uri="https://s.example/1",
                                    status_list=new_status_list(16), issuer="https://s.example")
    h, p, _ = token.split(".")
    forged = f"{h}.{p}.{_b64u(FORGED_SIG)}"
    with pytest.raises(SignatureInvalid) as info:
        verify_status_list_token(forged, public_key_jwk=_jwk(POINTS[name]))
    assert type(info.value) is SignatureInvalid
    assert "could not verify" in str(info.value)
    # control: the genuine token under the genuine key
    assert verify_status_list_token(token, public_key_jwk=_jwk(signer.public_key_raw()))
    assert StatusListError  # imported for the family the lane maps its own failures to


# ------------------------------------------------------ Data Integrity (JCS and RDFC) #

def _unsigned_vc() -> dict:
    return {"@context": [V2], "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "credentialSubject": {"id": "did:example:holder"}}


def _forged_di(suite, signer: Ed25519SigningKey) -> dict:
    secured = suite.add_proof(_unsigned_vc(), signing_key=signer,
                              verification_method="did:example:issuer#k", created=NOW)
    proof = dict(secured["proof"], proofValue=encode_multibase(FORGED_SIG))
    return {**secured, "proof": proof}


@pytest.mark.parametrize("name", POINT_IDS)
def test_eddsa_jcs_refuses(name):
    signer = Ed25519SigningKey.generate(kid="s")
    suite = EddsaJcsProofSuite()
    with pytest.raises(SignatureInvalid) as info:
        suite.verify(_forged_di(suite, signer), public_key_jwk=_jwk(POINTS[name]), now=NOW)
    assert type(info.value) is SignatureInvalid
    assert "malformed public key" not in str(info.value)
    assert "small-order" in str(info.value) or "canonical" in str(info.value)


def test_eddsa_jcs_wrong_length_x_keeps_its_class():
    signer = Ed25519SigningKey.generate(kid="s")
    suite = EddsaJcsProofSuite()
    with pytest.raises(SignatureInvalid, match="malformed public key"):
        suite.verify(_forged_di(suite, signer), public_key_jwk=_jwk(bytes(31)), now=NOW)


def test_eddsa_jcs_control():
    signer = Ed25519SigningKey.generate(kid="s")
    suite = EddsaJcsProofSuite()
    jwk = _jwk(signer.public_key_raw())
    with pytest.raises(SignatureInvalid, match="does not verify"):
        suite.verify(_forged_di(suite, signer), public_key_jwk=jwk, now=NOW)
    good = suite.add_proof(_unsigned_vc(), signing_key=signer,
                           verification_method="did:example:issuer#k", created=NOW)
    assert suite.verify(good, public_key_jwk=jwk, now=NOW).issuer == "did:example:issuer"


@pytest.mark.parametrize("name", POINT_IDS)
def test_eddsa_rdfc_refuses(name):
    pytest.importorskip("pyld")
    signer = Ed25519SigningKey.generate(kid="s")
    suite = DataIntegrityProofSuite()
    with pytest.raises(ProofError) as info:
        suite.verify(_forged_di(suite, signer), public_key_jwk=_jwk(POINTS[name]), now=NOW)
    assert type(info.value) is SignatureInvalid
    assert "unusable Ed25519 public key" in str(info.value)


def test_eddsa_rdfc_wrong_length_x_keeps_its_class():
    pytest.importorskip("pyld")
    signer = Ed25519SigningKey.generate(kid="s")
    suite = DataIntegrityProofSuite()
    with pytest.raises(ProofMalformed) as info:
        suite.verify(_forged_di(suite, signer), public_key_jwk=_jwk(bytes(31)), now=NOW)
    assert type(info.value) is ProofMalformed
    assert "malformed Ed25519 public key" in str(info.value)


def test_eddsa_rdfc_control():
    pytest.importorskip("pyld")
    signer = Ed25519SigningKey.generate(kid="s")
    suite = DataIntegrityProofSuite()
    jwk = _jwk(signer.public_key_raw())
    with pytest.raises(SignatureInvalid):
        suite.verify(_forged_di(suite, signer), public_key_jwk=jwk, now=NOW)
    good = suite.add_proof(_unsigned_vc(), signing_key=signer,
                           verification_method="did:example:issuer#k", created=NOW)
    assert suite.verify(good, public_key_jwk=jwk, now=NOW).issuer == "did:example:issuer"


@pytest.mark.parametrize("name", POINT_IDS)
def test_eddsa_jcs_through_verify_credential_is_typed_per_item(name):
    """The pipeline path: a did:key verificationMethod holding the point; verify_many
    returns a typed per-item error instead of aborting the batch."""
    signer = Ed25519SigningKey.generate(kid="s")
    suite = EddsaJcsProofSuite()
    did = _did_key(POINTS[name])
    secured = suite.add_proof(dict(_unsigned_vc(), issuer=did), signing_key=signer,
                              verification_method=f"{did}#{did[len('did:key:'):]}", created=NOW)
    secured["proof"]["proofValue"] = encode_multibase(FORGED_SIG)
    out = verify_many([secured, secured], policy=VerificationPolicy())
    assert [r.ok for r in out] == [False, False]
    for r in out:
        assert isinstance(r.error, OpenvcError)
        assert type(r.error) is SignatureInvalid
        assert "small-order" in str(r.error) or "canonical" in str(r.error)


# ------------------------------------------------------------------------ did:webvh #

def _webvh_genesis_log(update_key_raw: bytes) -> tuple[str, str]:
    """A hand-built genesis log whose single updateKey is *update_key_raw*, with a proof
    (the forged signature) by it. Returns (did, jsonl)."""
    multikey = encode_multibase(bytes([0xED, 0x01]) + update_key_raw)
    placeholder = "{SCID}"
    state = {"@context": ["https://www.w3.org/ns/did/v1"],
             "id": f"did:webvh:{placeholder}:example.com"}
    entry = {"versionId": placeholder, "versionTime": "2026-01-01T00:00:00Z",
             "parameters": {"method": "did:webvh:1.0", "scid": placeholder,
                            "updateKeys": [multikey]},
             "state": state}
    scid = _multihash_b58(_jcs(entry))
    entry = json.loads(json.dumps(entry).replace(placeholder, scid))
    did = f"did:webvh:{scid}:example.com"
    entry_hash = _multihash_b58(_jcs({**entry, "versionId": scid}))
    entry["versionId"] = f"1-{entry_hash}"
    config = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
              "verificationMethod": f"did:key:{multikey}#{multikey}",
              "created": "2026-01-01T00:00:00Z", "proofPurpose": "assertionMethod"}
    entry["proof"] = [dict(config, proofValue=encode_multibase(FORGED_SIG))]
    return did, json.dumps(entry)


@pytest.mark.parametrize("name", POINT_IDS)
def test_webvh_update_key_of_small_order_is_refused(name):
    """The resolver's own family (a DidError), not a bare InvalidKey leaking out of it."""
    did, log = _webvh_genesis_log(POINTS[name])
    with pytest.raises(OpenvcError) as info:
        DidWebvhResolver(fetch=lambda _url: log).resolve(did)
    assert type(info.value) is DidWebvhError
    assert "not a usable Ed25519 key" in str(info.value)


def test_webvh_control_valid_update_key_same_forged_proof():
    did, log = _webvh_genesis_log(_valid_raw())
    with pytest.raises(DidWebvhError, match="no valid eddsa-jcs-2022 proof"):
        DidWebvhResolver(fetch=lambda _url: log).resolve(did)


def test_webvh_wrong_length_update_key_keeps_its_class():
    did, log = _webvh_genesis_log(bytes(31))
    with pytest.raises(DidWebvhError, match="not an Ed25519 multikey"):
        DidWebvhResolver(fetch=lambda _url: log).resolve(did)


def test_webvh_issuer_in_a_batch_is_a_per_item_error():
    """Through the pipeline a refused log is KeyResolutionFailed, like any log the resolver
    refuses; verify_many returns it per item and the batch carries on."""
    from openvc.did.base import DidResolverRegistry
    from openvc.verify import KeyResolutionFailed

    did, log = _webvh_genesis_log(POINTS["identity"])
    resolver = DidResolverRegistry([DidWebvhResolver(fetch=lambda _url: log)])
    token = _forged_vc_jwt(did)
    out = verify_many([token, token], policy=VerificationPolicy(), resolver=resolver)
    assert [r.ok for r in out] == [False, False]
    for r in out:
        assert type(r.error) is KeyResolutionFailed
        assert "not a usable Ed25519 key" in str(r.error)


# -------------------------------------------------------------------------- COSE #

def _sign1(protected_alg: int = -8):
    from openvc import cbor, cose

    return cose.CoseSign1(protected=cbor.encode({1: protected_alg}),
                          protected_header={1: protected_alg}, unprotected={},
                          payload=b"p", signature=FORGED_SIG)


@pytest.mark.parametrize("name", POINT_IDS)
def test_cose_sign1_refuses_with_coseerror(name):
    from openvc import cose

    with pytest.raises(OpenvcError) as info:
        cose.verify_sign1(_sign1(), public_jwk=_jwk(POINTS[name]))
    assert type(info.value) is cose.CoseError
    assert "unusable" in str(info.value)


def test_cose_sign1_wrong_length_x_is_still_the_key_class():
    """Rule C: the general KeyBackendError mapping of verify_sign1 is #391's, not this PR's."""
    from openvc import cose

    with pytest.raises(InvalidKey) as info:
        cose.verify_sign1(_sign1(), public_jwk=_jwk(bytes(31)))
    assert type(info.value) is InvalidKey


def _device_auth_inputs(device_x: bytes):
    from types import SimpleNamespace

    from openvc import cbor

    inner = cbor.encode({})
    ns_tag = cbor.CborTag(cbor.TAG_ENCODED_CBOR, inner,
                          raw=cbor.encode(cbor.CborTag(cbor.TAG_ENCODED_CBOR, inner)))
    sign1 = [cbor.encode({1: -8}), {}, None, FORGED_SIG]
    document = {"deviceSigned": {"nameSpaces": ns_tag,
                                 "deviceAuth": {"deviceSignature": sign1}}}
    parts = SimpleNamespace(
        doc_type="org.iso.18013.5.1.mDL",
        mso={"deviceKeyInfo": {"deviceKey": {1: 1, -1: 6, -2: device_x}}})
    return document, parts


@pytest.mark.parametrize("name", POINT_IDS)
def test_mdoc_device_auth_maps_the_cose_refusal(name):
    """mdoc turns the CoseError into its own MdocDeviceAuthError (holder binding failed)."""
    from openvc.mdoc import MdocDeviceAuthError, _verify_device_auth

    document, parts = _device_auth_inputs(POINTS[name])
    with pytest.raises(OpenvcError) as info:
        _verify_device_auth(document, parts, b"\x80", None)
    assert type(info.value) is MdocDeviceAuthError
    assert "could not be checked" in str(info.value)


def test_mdoc_device_auth_control_valid_key():
    from openvc.mdoc import MdocDeviceAuthError, _verify_device_auth

    document, parts = _device_auth_inputs(_valid_raw())
    with pytest.raises(MdocDeviceAuthError, match="does not verify"):
        _verify_device_auth(document, parts, b"\x80", None)


# --------------------------------------------------------------------- VP-JWT / WRPRC #

@pytest.mark.parametrize("name", POINT_IDS)
def test_vp_jwt_holder_key_refuses(name):
    from openvc.proof.vp_jwt import VpJwtProofSuite

    now = int(time.time())
    token = _forged_jws({"alg": "EdDSA", "typ": "JWT"},
                        {"iss": "did:example:h", "aud": "https://v.example", "nonce": "n",
                         "iat": now, "nbf": now, "vp": {"type": ["VerifiablePresentation"]}})
    with pytest.raises(ProofError) as info:
        VpJwtProofSuite().verify(token, audience="https://v.example", nonce="n",
                                 holder_key_jwk=_jwk(POINTS[name]))
    assert type(info.value) is SignatureInvalid
    assert "small-order" in str(info.value) or "canonical" in str(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_wrprc_signature_check_maps_it_to_its_own_family(name):
    """The WRPRC lane maps every KeyBackendError to RpRegistrationError; pinned on its
    signature step (the registrar key is a JWK by then). The full certificate path is
    pinned below, through `verify_rp_registration_certificate`."""
    from openvc.rp_registration import RpRegistrationError, _verify_signature

    with pytest.raises(OpenvcError) as info:
        _verify_signature("jwt", {"alg": "EdDSA"}, _jwk(POINTS[name]),
                          signing_input=b"x.y", signature=FORGED_SIG, sign1=None)
    assert type(info.value) is RpRegistrationError
    assert _says_point(info.value)


def test_wrprc_cose_form_maps_it_too():
    from openvc.rp_registration import RpRegistrationError, _verify_signature

    with pytest.raises(OpenvcError) as info:
        _verify_signature("cwt", {}, _jwk(POINTS["identity"]),
                          signing_input=b"", signature=b"", sign1=_sign1())
    assert type(info.value) is RpRegistrationError
    assert _says_point(info.value)


# ------------------------------------------------------------- P-256 is untouched #

def test_p256_vc_jwt_still_verifies():
    from openvc.keys import P256SigningKey

    key = P256SigningKey.generate(kid="p")
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": "did:example:p",
          "credentialSubject": {"id": "did:example:holder"}}
    token = VcJwtProofSuite().sign(vc, signing_key=key)
    assert VcJwtProofSuite().verify(
        token, public_key_jwk=key.public_jwk()).issuer == "did:example:p"


def test_ecdsa_jcs_2019_still_verifies():
    from openvc.keys import P256SigningKey
    from openvc.proof.di_jcs import EcdsaJcsProofSuite

    key = P256SigningKey.generate(kid="p")
    suite = EcdsaJcsProofSuite()
    secured = suite.add_proof(_unsigned_vc(), signing_key=key,
                              verification_method="did:example:issuer#k", created=NOW)
    result = suite.verify(secured, public_key_jwk=key.public_jwk(), now=NOW)
    assert result.issuer == "did:example:issuer"


# =========================================================================== #
# Review follow-ups (PR #442): F1 private-member JWK, F2 helper totality,
# F3 certificate-borne / COSE_Key-borne keys end to end
# =========================================================================== #

# ------------------------------------------------ F1: a JWK that carries `d` (VC-JWT) #

def _private_jwk_fixture():
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(b"leaked-d").digest()
    did = "did:web:issuer.example"
    key = Ed25519SigningKey(Ed25519PrivateKey.from_private_bytes(seed), kid=f"{did}#k")
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(key.public_key_raw()), "d": _b64u(seed)}
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
          "credentialSubject": {"id": "did:example:holder"}}
    return did, key, jwk, VcJwtProofSuite().sign(vc, signing_key=key)


def test_vc_jwt_pinned_jwk_with_d_still_verifies_as_on_main():
    """PyJWT returns a private key object for a JWK with `d` and verifies with its public
    half. The point check looks at that half; behaviour for the key is unchanged."""
    _, _, jwk, token = _private_jwk_fixture()
    assert VcJwtProofSuite().verify(token, public_key_jwk=jwk).issuer.startswith("did:web:")


def test_vc_jwt_did_web_document_with_d_still_verifies_as_on_main():
    from openvc.did.base import DidResolverRegistry
    from openvc.did.did_web import DidWebResolver

    did, _, jwk, token = _private_jwk_fixture()
    doc = {"@context": ["https://www.w3.org/ns/did/v1"], "id": did,
           "verificationMethod": [{"id": f"{did}#k", "type": "JsonWebKey2020",
                                   "controller": did, "publicKeyJwk": jwk}],
           "assertionMethod": [f"{did}#k"], "authentication": [f"{did}#k"]}
    resolver = DidResolverRegistry([DidWebResolver(fetch=lambda _url: doc)])
    assert verify_credential(token, resolver=resolver).issuer == did


@pytest.mark.parametrize("name", POINT_IDS)
def test_vc_jwt_hostile_x_without_d_is_the_point_refusal(name):
    """No `d`: nothing here depends on PyJWT, so exact class and point text."""
    with pytest.raises(SignatureInvalid) as info:
        VcJwtProofSuite().verify(_forged_vc_jwt("did:example:x"),
                                 public_key_jwk=_jwk(POINTS[name]))
    assert _says_point(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_vc_jwt_hostile_x_next_to_d_is_never_accepted(name):
    """A hostile `x` next to a real `d`. What happens first depends on PyJWT, so this branches
    on what the library did with the JWK, not on a version string: PyJWT 2.13.0 loads it from
    `d` and ignores `x`; newer releases refuse the JWK ("Public key does not match private
    key") before the point check runs. Either way the forged credential is refused with a
    `ProofError` and is never accepted."""
    from jwt.algorithms import OKPAlgorithm

    _, _, jwk, _ = _private_jwk_fixture()
    hostile = dict(jwk, x=_b64u(POINTS[name]))
    try:
        OKPAlgorithm.from_jwk(json.dumps(hostile))
        loads = True
    except Exception:
        loads = False
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite().verify(_forged_vc_jwt("did:example:x"), public_key_jwk=hostile)
    if loads:
        # the verifying key is the one derived from `d`: the forged signature fails as a
        # plain signature failure, and the hostile `x` was never the key
        assert type(info.value) is SignatureInvalid
        assert not _says_point(info.value)
    else:
        assert type(info.value) is ProofError
        assert str(info.value).startswith(_LOAD)


# class and openvc's own text recorded on origin/main for each bad-key shape on this lane.
# Text that PyJWT or `cryptography` wrote after "could not load EdDSA key from JWK: " is NOT
# pinned: it differs between PyJWT releases ("a string value" / "a string or bytes value"), and
# only the openvc part is ours to hold constant.
_LOAD = "could not load EdDSA key from JWK: "
_PIN = "EdDSA requires an OKP Ed25519 key, got "
_MAIN_SHAPES = {
    "x31": (lambda g: {"kty": "OKP", "crv": "Ed25519", "x": _b64u(bytes(31))}, _LOAD),
    "x33": (lambda g: {"kty": "OKP", "crv": "Ed25519", "x": _b64u(g + b"\0")}, _LOAD),
    "x-empty": (lambda g: {"kty": "OKP", "crv": "Ed25519", "x": ""}, _LOAD),
    "x-missing": (lambda g: {"kty": "OKP", "crv": "Ed25519"}, _LOAD),
    "x-int": (lambda g: {"kty": "OKP", "crv": "Ed25519", "x": 5}, _LOAD),
    "x-null": (lambda g: {"kty": "OKP", "crv": "Ed25519", "x": None}, _LOAD),
    "x-notb64": (lambda g: {"kty": "OKP", "crv": "Ed25519", "x": "!!!"}, _LOAD),
    "crv-x25519": (lambda g: {"kty": "OKP", "crv": "X25519", "x": _b64u(g)},
                   _PIN + "kty='OKP' crv='X25519'"),
    "crv-ed448": (lambda g: {"kty": "OKP", "crv": "Ed448", "x": _b64u(g)},
                  _PIN + "kty='OKP' crv='Ed448'"),
    "kty-ec": (lambda g: {"kty": "EC", "crv": "Ed25519", "x": _b64u(g)},
               _PIN + "kty='EC' crv='Ed25519'"),
    "none": (lambda g: None, "EdDSA requires a JWK object, got NoneType"),
    "list": (lambda g: [1], "EdDSA requires a JWK object, got list"),
    "empty": (lambda g: {}, _PIN + "kty=None crv=None"),
}


@pytest.mark.parametrize("shape", list(_MAIN_SHAPES))
def test_vc_jwt_other_bad_keys_keep_main_class_and_openvc_text(shape):
    make, prefix = _MAIN_SHAPES[shape]
    _, key, _, token = _private_jwk_fixture()
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite().verify(token, public_key_jwk=make(key.public_key_raw()))
    assert type(info.value) is ProofError
    assert str(info.value).startswith(prefix)
    assert not _says_point(info.value)


# ----------------------------------------------- F2: check_ed25519_point is total #

@pytest.mark.parametrize("bad, text", [
    (bytes(33), "got 33 bytes"), (b"", "got 0 bytes"), (bytes(31), "got 31 bytes"),
    ("x" * 32, "got str"), (None, "got NoneType"), (5, "got int")])
def test_helper_rejects_anything_that_is_not_32_bytes_typed(bad, text):
    from openvc.keys import check_ed25519_point

    with pytest.raises(InvalidKey, match=text) as info:
        check_ed25519_point(bad)
    assert type(info.value) is InvalidKey          # not UnusablePublicKey: not a point at all


def test_helper_accepts_a_bytearray_key():
    from openvc.keys import check_ed25519_point

    check_ed25519_point(bytearray(_valid_raw()))
    with pytest.raises(InvalidKey) as info:
        check_ed25519_point(bytearray(POINTS["identity"]))
    assert type(info.value) is _unusable()


def test_helper_message_is_neutral_by_default_and_names_the_jwk_for_canonical_public_jwk():
    from openvc.keys import canonical_public_jwk, check_ed25519_point

    with pytest.raises(InvalidKey) as info:
        check_ed25519_point(POINTS["identity"])
    assert "JWK" not in str(info.value)
    with pytest.raises(InvalidKey, match="JWK member 'x' is a small-order Ed25519 point"):
        canonical_public_jwk(_jwk(POINTS["identity"]))


# ----------------------------------------- F3: certificate / COSE_Key borne keys #

def _x509_helpers():
    """Builders shared by the end-to-end cases below (re-implemented here: tests/ is not a
    package). A certificate whose SPKI is a small-order point is built with cryptography's
    own CertificateBuilder; main accepts forged artefacts under it."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.x509.oid import NameOID

    class H:
        pass

    h = H()
    h.x509, h.hashes, h.ser, h.ec = x509, hashes, serialization, ec
    h.Ed, h.dt = Ed25519PublicKey, dt
    h.name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    h.NameOID = NameOID
    # mdoc (ISO 18013-5 9.3.3) wants a countryName on both the DS and its IACA
    h.cname = lambda cn: x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "UT"),
                                    x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return h


def _cert(h, subject, issuer, pub, signer_key, exts, *, not_before, not_after):
    b = (h.x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(pub).serial_number(h.x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after))
    for ext, critical in exts:
        b = b.add_extension(ext, critical)
    return b.sign(signer_key, h.hashes.SHA256())


def _der(h, cert) -> bytes:
    return cert.public_bytes(h.ser.Encoding.DER)


def _ca_exts(h):
    return [(h.x509.BasicConstraints(ca=True, path_length=None), True),
            (h.x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)]


# ----- mdoc (ISO 18013-5): IssuerAuth DS certificate and DeviceAuth MSO deviceKey ----- #

_DOCTYPE = "org.iso.18013.5.1.mDL"
_NS = "org.iso.18013.5.1"
_ORIGIN = "https://verifier.example"
_NONCE = "abcdefgh-nonce-0123456789"


class _MdocFixture:
    def __init__(self):
        import datetime as dt

        from openvc.openid4vp import dcapi_session_transcript

        self.h = h = _x509_helpers()
        self.now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        self.past = self.now - dt.timedelta(days=3650)
        self.future = self.now + dt.timedelta(days=3650)
        self.iaca_key = h.ec.generate_private_key(h.ec.SECP256R1())
        self.iaca = _cert(h, h.cname("iaca"), h.cname("iaca"), self.iaca_key.public_key(),
                          self.iaca_key, _ca_exts(h), not_before=self.past,
                          not_after=self.future)
        self.transcript = dcapi_session_transcript(_ORIGIN, _NONCE)

    def ds_cert(self, pub) -> bytes:
        h = self.h
        return _der(h, _cert(
            h, h.cname("ds"), h.cname("iaca"), pub, self.iaca_key,
            [(h.x509.BasicConstraints(ca=False, path_length=None), True),
             (h.x509.ExtendedKeyUsage([h.x509.ObjectIdentifier("1.0.18013.5.1.2")]), False)],
            not_before=self.past, not_after=self.future))

    def build(self, *, issuer_raw: bytes | None = None, device_raw: bytes | None = None) -> bytes:
        """A one-document DeviceResponse. With *issuer_raw* the DS certificate carries that
        Ed25519 key (IssuerAuth signed with the forged signature); with *device_raw* the MSO
        deviceKey is that OKP key (DeviceSignature forged). The other half is a genuine
        P-256 signature."""
        import hashlib

        from cryptography.hazmat.primitives.asymmetric import ec

        from openvc import cbor
        from openvc.keys import P256SigningKey

        h = self.h

        def tdate(when):
            return cbor.CborTag(0, when.replace(tzinfo=None).isoformat(timespec="seconds") + "Z")

        def sign1(payload, signer, alg, *, x5chain=None, detached=False):
            prot = cbor.encode({1: alg})
            tbs = cbor.encode(["Signature1", prot, b"", payload])
            sig = FORGED_SIG if signer is None else P256SigningKey(signer, kid="k").sign(tbs)
            return [prot, ({} if x5chain is None else {33: x5chain}),
                    (None if detached else payload), sig]

        raw_item = cbor.encode(cbor.CborTag(24, cbor.encode(
            {"digestID": 0, "random": bytes(16), "elementIdentifier": "family_name",
             "elementValue": "Doe"})))
        dev_priv = ec.generate_private_key(ec.SECP256R1())
        if device_raw is None:
            nums = dev_priv.public_key().public_numbers()
            cose_key = {1: 2, -1: 1, -2: nums.x.to_bytes(32, "big"),
                        -3: nums.y.to_bytes(32, "big")}
        else:
            cose_key = {1: 1, -1: 6, -2: device_raw}
        mso = {"version": "1.0", "digestAlgorithm": "SHA-256",
               "valueDigests": {_NS: {0: hashlib.sha256(raw_item).digest()}},
               "deviceKeyInfo": {"deviceKey": cose_key}, "docType": _DOCTYPE,
               "validityInfo": {"signed": tdate(self.now), "validFrom": tdate(self.past),
                                "validUntil": tdate(self.future)}}
        mso_tagged = cbor.encode(cbor.CborTag(24, cbor.encode(mso)))
        if issuer_raw is None:
            ds = ec.generate_private_key(ec.SECP256R1())
            issuer_auth = sign1(mso_tagged, ds, -7, x5chain=self.ds_cert(ds.public_key()))
        else:
            issuer_auth = sign1(mso_tagged, None, -8,
                                x5chain=self.ds_cert(h.Ed.from_public_bytes(issuer_raw)))
        dns = cbor.encode(cbor.CborTag(24, cbor.encode({})))
        device_authentication = cbor.encode(cbor.CborTag(24, cbor.encode(
            ["DeviceAuthentication", cbor.CborRaw(self.transcript), _DOCTYPE, cbor.CborRaw(dns)])))
        if device_raw is None:
            device_sig = sign1(device_authentication, dev_priv, -7, detached=True)
        else:
            device_sig = sign1(device_authentication, None, -8, detached=True)
        return cbor.encode({"version": "1.0", "status": 0, "documents": [{
            "docType": _DOCTYPE,
            "issuerSigned": {"nameSpaces": {_NS: [cbor.decode(raw_item)]},
                             "issuerAuth": issuer_auth},
            "deviceSigned": {"nameSpaces": cbor.decode(dns),
                             "deviceAuth": {"deviceSignature": device_sig}}}]})


@pytest.fixture(scope="module")
def mdoc_fx():
    return _MdocFixture()


@pytest.mark.parametrize("name", POINT_IDS)
def test_mdoc_issuer_auth_under_a_small_order_ds_certificate(mdoc_fx, name):
    from openvc import mdoc

    response = mdoc_fx.build(issuer_raw=POINTS[name])
    with pytest.raises(OpenvcError) as info:
        mdoc.verify_device_response(response, trust_anchors=[mdoc_fx.iaca],
                                    session_transcript=mdoc_fx.transcript, now=mdoc_fx.now)
    assert type(info.value) is mdoc.MdocSignatureInvalid
    assert _says_point(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_mdoc_verify_issuer_signed_under_a_small_order_ds_certificate(mdoc_fx, name):
    from openvc import cbor, mdoc

    document = cbor.decode(mdoc_fx.build(issuer_raw=POINTS[name]))["documents"][0]
    with pytest.raises(OpenvcError) as info:
        mdoc.verify_issuer_signed(document, trust_anchors=[mdoc_fx.iaca], now=mdoc_fx.now)
    assert type(info.value) is mdoc.MdocSignatureInvalid
    assert _says_point(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_mdoc_device_auth_under_a_small_order_device_key(mdoc_fx, name):
    from openvc import mdoc

    response = mdoc_fx.build(device_raw=POINTS[name])
    with pytest.raises(OpenvcError) as info:
        mdoc.verify_device_response(response, trust_anchors=[mdoc_fx.iaca],
                                    session_transcript=mdoc_fx.transcript, now=mdoc_fx.now)
    assert type(info.value) is mdoc.MdocDeviceAuthError
    assert _says_point(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_verify_vp_token_mso_mdoc_under_a_small_order_device_key(mdoc_fx, name):
    from openvc import mdoc
    from openvc.openid4vp import verify_vp_token

    dcql = {"credentials": [{"id": "q", "format": "mso_mdoc",
                             "meta": {"doctype_value": _DOCTYPE}}]}
    response = mdoc_fx.build(device_raw=POINTS[name])
    with pytest.raises(OpenvcError) as info:
        verify_vp_token({"q": [_b64u(response)]}, dcql_query=dcql, nonce=_NONCE,
                        expected_origins=[_ORIGIN], trust_anchors=[mdoc_fx.iaca],
                        now=mdoc_fx.now)
    assert type(info.value) is mdoc.MdocDeviceAuthError
    assert _says_point(info.value)


def test_mdoc_controls_a_genuine_response_verifies_and_a_valid_ed25519_key_is_not_refused(
        mdoc_fx):
    from openvc import mdoc

    ok = mdoc.verify_device_response(
        mdoc_fx.build(), trust_anchors=[mdoc_fx.iaca],
        session_transcript=mdoc_fx.transcript, now=mdoc_fx.now)
    assert len(ok) == 1 and ok[0].device_signed
    # a valid Ed25519 key in either slot gets as far as the (forged) signature
    with pytest.raises(mdoc.MdocSignatureInvalid, match="does not verify"):
        mdoc.verify_device_response(
            mdoc_fx.build(issuer_raw=_valid_raw()), trust_anchors=[mdoc_fx.iaca],
            session_transcript=mdoc_fx.transcript, now=mdoc_fx.now)
    with pytest.raises(mdoc.MdocDeviceAuthError, match="does not verify"):
        mdoc.verify_device_response(
            mdoc_fx.build(device_raw=_valid_raw()), trust_anchors=[mdoc_fx.iaca],
            session_transcript=mdoc_fx.transcript, now=mdoc_fx.now)


# ----- LoTE (TS 119 602): the signer certificate's SPKI ----- #

class _LoteFixture:
    URI = "http://uri.etsi.org/19602"

    def __init__(self):
        import base64 as b64
        import datetime as dt

        from openvc.trustlist import lote

        self.h = h = _x509_helpers()
        self.lote = lote
        self.now = dt.datetime(2026, 7, 22, tzinfo=dt.timezone.utc)
        self._b64 = lambda c: b64.b64encode(_der(h, c)).decode()
        self.nb, self.na = self.now - dt.timedelta(days=30), self.now + dt.timedelta(days=3650)
        self.op_key = h.ec.generate_private_key(h.ec.SECP256R1())
        self.op_name = h.name("Operator CA")
        self.op_ca = _cert(h, self.op_name, self.op_name, self.op_key.public_key(),
                           self.op_key, _ca_exts(h), not_before=self.nb, not_after=self.na)
        self.reg_key = h.ec.generate_private_key(h.ec.SECP256R1())
        self.reg_name = h.name("Registrar Root CA")
        self.reg = _cert(h, self.reg_name, self.reg_name, self.reg_key.public_key(),
                         self.reg_key, _ca_exts(h), not_before=self.nb, not_after=self.na)

    def doc(self, seq: int = 1) -> dict:
        URI, lote = self.URI, self.lote
        scheme = {
            "LoTEVersionIdentifier": 1, "LoTESequenceNumber": seq,
            "LoTEType": lote.LoteType.EU_WRPRC_PROVIDERS,
            "SchemeOperatorName": [{"lang": "en", "value": "European Commission"}],
            "StatusDeterminationApproach": f"{URI}/WRPRCrovidersList/StatusDetn/EU",
            "SchemeTypeCommunityRules": [
                {"lang": "en", "uriValue": f"{URI}/WRPRCProvidersList/schemerules/EU"}],
            "SchemeTerritory": "EU", "ListIssueDateTime": "2026-07-01T00:00:00Z",
            "NextUpdate": "2026-12-01T00:00:00Z"}
        entity = {
            "TrustedEntityInformation": {
                "TEName": [{"lang": "en", "value": "Registrar"}],
                "TEAddress": {
                    "TEPostalAddress": [{"lang": "en", "StreetAddress": "Calle Uno 1",
                                         "Country": "ES"}],
                    "TEElectronicAddress": [{"lang": "en",
                                             "uriValue": "mailto:registrar@example.es"}]},
                "TEInformationURI": [{"lang": "en", "uriValue": "https://registrar.example.es/i"}]},
            "TrustedEntityServices": [{"ServiceInformation": {
                "ServiceName": [{"lang": "en", "value": "WRPRC issuance"}],
                "ServiceTypeIdentifier": lote.LoteServiceType.WRPRC_ISSUANCE,
                "ServiceDigitalIdentity": {"X509Certificates": [{"val": self._b64(self.reg)}]}}}]}
        return {"LoTE": {"ListAndSchemeInformation": scheme, "TrustedEntitiesList": [entity]}}

    def signer_leaf(self, raw: bytes):
        h = self.h
        name = h.x509.Name([
            h.x509.NameAttribute(h.NameOID.COUNTRY_NAME, "EU"),
            h.x509.NameAttribute(h.NameOID.ORGANIZATION_NAME, "European Commission"),
            h.x509.NameAttribute(h.NameOID.COMMON_NAME, "LoTE signer")])
        return _cert(h, name, self.op_name, h.Ed.from_public_bytes(raw), self.op_key,
                     [(h.x509.BasicConstraints(False, None), True)],
                     not_before=self.nb, not_after=self.na)

    def token(self, raw: bytes, *, pin: str):
        leaf = self.signer_leaf(raw)
        head = {"alg": "EdDSA",
                "x5c": [self._b64(leaf)] + ([self._b64(self.op_ca)] if pin == "ca" else [])}
        signing_input = (_b64u(json.dumps(head, separators=(",", ":")).encode()) + "."
                         + _b64u(json.dumps(self.doc(), separators=(",", ":")).encode()))
        token = signing_input + "." + _b64u(FORGED_SIG)
        return token, (self.op_ca if pin == "ca" else leaf)


@pytest.fixture(scope="module")
def lote_fx():
    return _LoteFixture()


@pytest.mark.parametrize("pin", ["leaf", "ca"])
@pytest.mark.parametrize("name", POINT_IDS)
def test_consume_lote_under_a_small_order_signer_certificate(lote_fx, name, pin):
    from openvc.trustlist.errors import TrustListSignatureError
    from openvc.trustlist.lote import consume_lote

    token, pinned = lote_fx.token(POINTS[name], pin=pin)
    with pytest.raises(OpenvcError) as info:
        consume_lote(token, expected_signer_certs=[pinned], now=lote_fx.now)
    assert type(info.value) is TrustListSignatureError
    assert _says_point(info.value)


def test_consume_lote_control_valid_key_same_forged_signature(lote_fx):
    from openvc.trustlist.errors import TrustListSignatureError
    from openvc.trustlist.lote import consume_lote

    token, pinned = lote_fx.token(_valid_raw(), pin="leaf")
    with pytest.raises(TrustListSignatureError, match="verification failed"):
        consume_lote(token, expected_signer_certs=[pinned], now=lote_fx.now)


@pytest.mark.parametrize("name", ["identity", "noncanonical-identity"])
def test_walk_lote_stages_a_pointed_list_signed_under_a_small_order_certificate(lote_fx, name):
    """The walk does not abort and does not trust the list: the pointed LoTE is staged as a
    `signature` problem and contributes no anchor."""
    from openvc.keys import P256SigningKey
    from openvc.trustlist.lote import LoteType, walk_lote

    h = lote_fx.h
    op_key = h.ec.generate_private_key(h.ec.SECP256R1())
    op_name = h.x509.Name([
        h.x509.NameAttribute(h.NameOID.COUNTRY_NAME, "EU"),
        h.x509.NameAttribute(h.NameOID.ORGANIZATION_NAME, "European Commission"),
        h.x509.NameAttribute(h.NameOID.COMMON_NAME, "LoTE signer")])
    op_cert = _cert(h, op_name, op_name, op_key.public_key(), op_key,
                    [(h.x509.BasicConstraints(False, None), True)],
                    not_before=lote_fx.nb, not_after=lote_fx.na)
    pointed, voucher = lote_fx.token(POINTS[name], pin="leaf")
    root = lote_fx.doc(seq=0)
    root["LoTE"]["ListAndSchemeInformation"]["PointersToOtherLoTE"] = [{
        "LoTELocation": "https://pointed.example/lote.jwt",
        "ServiceDigitalIdentities": [{"X509Certificates": [{"val": lote_fx._b64(voucher)}]}],
        "LoTEQualifiers": [{"LoTEType": LoteType.EU_WRPRC_PROVIDERS,
                            "SchemeOperatorName": [{"lang": "en",
                                                    "value": "European Commission"}],
                            "MimeType": "application/jose"}]}]
    head = {"alg": "ES256", "x5c": [lote_fx._b64(op_cert)]}
    signing_input = (_b64u(json.dumps(head, separators=(",", ":")).encode()) + "."
                     + _b64u(json.dumps(root, separators=(",", ":")).encode()))
    root_token = (signing_input + "."
                  + _b64u(P256SigningKey(op_key, "k").sign(signing_input.encode())))

    def fetch(url):
        return (pointed if "pointed" in url else root_token).encode()

    result = walk_lote("https://root.example/lote.jwt", lote_signer_certs=[op_cert],
                       fetch=fetch, now=lote_fx.now)
    assert [p.stage for p in result.problems] == ["signature"]
    assert len(result.anchors) == 1          # the root's own registrar anchor only


# ----- WRPRC (TS 119 475): the registrar leaf certificate's SPKI ----- #

class _WrprcFixture:
    def __init__(self):
        import datetime as dt

        self.h = h = _x509_helpers()
        self.now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        self.at = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        self.nb, self.na = self.now - dt.timedelta(days=1), self.now + dt.timedelta(days=3650)
        self.root_key = h.ec.generate_private_key(h.ec.SECP256R1())
        self.root_name = h.name("Test Registrar Root")
        self.root = _cert(h, self.root_name, self.root_name, self.root_key.public_key(),
                          self.root_key, _ca_exts(h), not_before=self.nb, not_after=self.na)

    def claims(self) -> dict:
        iat = int(self.at.timestamp()) - 3600
        return {
            "sub": "VATES-B12345678", "name": "Acme Age Check",
            "sub_ln": "Acme Servicios Digitales SL", "country": "ES",
            "registry_uri": "https://registrar.example/ES", "policy_id": ["0.4.0.19475.3.1"],
            "certificate_policy": "https://registrar.example/cp", "iat": iat,
            "exp": int(self.at.timestamp()) + 86400,
            "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
            "intended_use_id": "age-verification",
            "purpose": [{"lang": "en-US", "value": "Checking the minimum age"}],
            "srv_description": [[{"lang": "en-US", "value": "Acme Age Check"}]],
            "credentials": [{"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
                             "claim": [{"path": ["address"]}]}],
            "supervisory_authority": {"email": "supervisory@aepd.es", "phone": "+34 900 000 000",
                                      "uri": "https://aepd.es/supervisory-authority"},
            "status": {"status_list": {"uri": "https://registrar.example/sl/1", "idx": 7}}}

    def leaf_der(self, raw: bytes) -> bytes:
        h = self.h
        return _der(h, _cert(
            h, h.name("Registrar Signing Key"), self.root_name, h.Ed.from_public_bytes(raw),
            self.root_key,
            [(h.x509.BasicConstraints(False, None), True),
             (h.x509.ExtendedKeyUsage([h.x509.ObjectIdentifier("0.4.0.19475.2.1")]), False)],
            not_before=self.nb, not_after=self.na))

    def jwt(self, raw: bytes) -> str:
        head = {"typ": "rc-wrp+jwt", "alg": "EdDSA",
                "x5c": [base64.b64encode(self.leaf_der(raw)).decode()]}
        return (_b64u(json.dumps(head, separators=(",", ":")).encode()) + "."
                + _b64u(json.dumps(self.claims(), separators=(",", ":")).encode())
                + "." + _b64u(FORGED_SIG))

    def cwt(self, raw: bytes) -> bytes:
        from openvc import cbor

        labels = {"sub": 2, "exp": 4, "nbf": 5, "iat": 6}
        body = cbor.encode({labels.get(k, k): v for k, v in self.claims().items()})
        protected = cbor.encode({1: -8, 16: "rc-wrp+cwt", 33: [self.leaf_der(raw)]})
        return cbor.encode([protected, {}, body, FORGED_SIG])


@pytest.fixture(scope="module")
def wrprc_fx():
    return _WrprcFixture()


@pytest.mark.parametrize("form", ["jwt", "cwt"])
@pytest.mark.parametrize("name", POINT_IDS)
def test_verify_rp_registration_certificate_under_a_small_order_leaf(wrprc_fx, name, form):
    from openvc.rp_registration import RpRegistrationError, verify_rp_registration_certificate

    artefact = (wrprc_fx.jwt if form == "jwt" else wrprc_fx.cwt)(POINTS[name])
    with pytest.raises(OpenvcError) as info:
        verify_rp_registration_certificate(artefact, trust_anchors=[wrprc_fx.root],
                                           now=wrprc_fx.at)
    assert type(info.value) is RpRegistrationError
    assert _says_point(info.value)


@pytest.mark.parametrize("form", ["jwt", "cwt"])
def test_wrprc_control_valid_key_same_forged_signature(wrprc_fx, form):
    from openvc.rp_registration import RpRegistrationError, verify_rp_registration_certificate

    artefact = (wrprc_fx.jwt if form == "jwt" else wrprc_fx.cwt)(_valid_raw())
    with pytest.raises(RpRegistrationError, match="verification failed"):
        verify_rp_registration_certificate(artefact, trust_anchors=[wrprc_fx.root],
                                           now=wrprc_fx.at)
