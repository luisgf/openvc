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
    with pytest.raises(InvalidKey):
        check_ed25519_point(POINTS[name])


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
    assert type(info.value) is InvalidKey
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
    assert type(info.value) is ProofError
    assert "could not load" in str(info.value)


@pytest.mark.parametrize("name", POINT_IDS)
def test_vc_jwt_suite_refuses_a_pinned_key(name):
    with pytest.raises(ProofError) as info:
        VcJwtProofSuite().verify(_forged_vc_jwt("did:example:x"),
                                 public_key_jwk=_jwk(POINTS[name]))
    assert type(info.value) is ProofError


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
        assert type(r.error) is ProofError


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
    assert type(info.value) is ProofError
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
    with pytest.raises(ProofMalformed) as info:
        suite.verify(_forged_di(suite, signer), public_key_jwk=_jwk(POINTS[name]), now=NOW)
    assert type(info.value) is ProofMalformed
    assert "unusable Ed25519 public key" in str(info.value)


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
    did, log = _webvh_genesis_log(POINTS[name])
    with pytest.raises(OpenvcError) as info:
        DidWebvhResolver(fetch=lambda _url: log).resolve(did)
    assert type(info.value) is InvalidKey


def test_webvh_control_valid_update_key_same_forged_proof():
    did, log = _webvh_genesis_log(_valid_raw())
    with pytest.raises(DidWebvhError, match="no valid eddsa-jcs-2022 proof"):
        DidWebvhResolver(fetch=lambda _url: log).resolve(did)


# -------------------------------------------------------------------------- COSE #

@pytest.mark.parametrize("name", POINT_IDS)
def test_cose_sign1_refuses_with_the_key_class(name):
    """COSE hands the key error through as it is (an OpenvcError; #391 tracks mapping it)."""
    from openvc import cbor, cose

    protected = cbor.encode({1: -8})        # alg: EdDSA
    sign1 = cose.CoseSign1(protected=protected, protected_header={1: -8}, unprotected={},
                           payload=b"p", signature=FORGED_SIG)
    with pytest.raises(InvalidKey) as info:
        cose.verify_sign1(sign1, public_jwk=_jwk(POINTS[name]))
    assert type(info.value) is InvalidKey


def test_webvh_issuer_in_a_batch_is_a_per_item_error():
    """Through the pipeline: the InvalidKey of a small-order updateKey is not swallowed into
    a pass and does not abort the batch; verify_many returns it as that item's error."""
    from openvc.did.base import DidResolverRegistry

    did, log = _webvh_genesis_log(POINTS["identity"])
    resolver = DidResolverRegistry([DidWebvhResolver(fetch=lambda _url: log)])
    token = _forged_vc_jwt(did)
    out = verify_many([token, token], policy=VerificationPolicy(), resolver=resolver)
    assert [r.ok for r in out] == [False, False]
    for r in out:
        assert isinstance(r.error, OpenvcError)
        assert type(r.error) is InvalidKey
