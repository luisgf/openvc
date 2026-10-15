"""
tests/test_lone_surrogate_typed.py — a lone UTF-16 surrogate stays inside the typed-error
boundary (#279).

JSON allows ``"\\ud800"``, an escape for a lone surrogate. ``json.loads`` and
``openvc._json.loads`` both accept it and return a ``str`` holding the code point, and no
UTF-8 encoding of such a string exists. Wherever openvc ran ``.encode("utf-8")`` on attacker
text outside a guarded block the result was a bare ``UnicodeEncodeError``. It is not an
``OpenvcError``, so ``verify_many`` / ``verify_many_async`` could not isolate it and the
whole batch aborted. No wrong-accept: every site failed closed, but untyped. Each site now
raises its lane's own error class (the fix is per site, so what verifies today still does).

THE FIXTURE SHAPE IS PART OF THE TEST. pyld's URDNA2015 hashes every quad that mentions a
*blank* node, inside ``jsonld.normalize``, which the suite already wraps. A quad about a
*named* node is never hashed, so its surrogate survives into the N-Quads string and reaches
the unguarded encode. A test on a subject without ``id`` therefore passes on ``main`` and
proves nothing. Every RDF and ``ecdsa-sd`` negative below uses a named-node document
(``credentialSubject.id`` present, no anonymous nested object), and each has a control with
the same shape and a benign string, so a negative cannot pass on a class that fires first:

* the Data Integrity controls reach the signature check (``SignatureInvalid``);
* the ``ecdsa-sd`` controls reach the base / per-statement signature check;
* the ``did:webvh`` control reaches the pre-rotation commitment check;
* a blank-node document is pinned too, as the shape that was already typed.

Issuers are always resolvable (``did:key``, or a stub ``did:webvh`` fetch of a recorded log),
so no negative can pass on a ``KeyResolutionFailed`` that comes first. Every assertion is on
the exact class (``type(exc) is …``).

Rows (the issue's numbering): 1 ``_canonize`` and its re-entries 1a ``ldp_vc`` VP, 1b VP-JWT
carrying an ``ldp_vc``, 1c the status-list second hop, 1d the issuer side; 2 / 3 ``ecdsa-sd``
verify, 3a ``add_base_proof``; 4 ``did:webvh`` pre-rotation; 5-7 OpenID4VCI; 8
``jwk_thumbprint``. The golden vectors (W3C vc-di-eddsa / vc-di-ecdsa, the ``did:webvh``
logs) live in their own suites and are the "no accept-set change" check; the surrogate-PAIR
controls at the end pin that a valid non-BMP character still signs and verifies everywhere.
"""
from __future__ import annotations

import asyncio
import copy
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openvc import _json, verify_credential, verify_many, verify_many_async
from openvc.aio import verify_credential_async
from openvc.did.base import AsyncDidResolverRegistry, DidResolverRegistry, as_async_resolver
from openvc.did.did_key import DidKeyResolver
from openvc.did.did_webvh import AsyncDidWebvhResolver, DidWebvhError, DidWebvhResolver
from openvc.errors import OpenvcError
from openvc.keys import (
    Ed25519SigningKey,
    InvalidKey,
    P256SigningKey,
    jwk_thumbprint,
    jwk_thumbprint_bytes,
)
from openvc.multibase import encode_multibase
from openvc.openid4vci import (
    CredentialRequestMalformed,
    parse_credential_request,
    peek_key_attestation,
    peek_proof_header,
    verify_credential_request_proofs,
)
from openvc.openid4vp import verify_vp_token
from openvc.proof._jws import sign_compact
from openvc.proof.data_integrity import DataIntegrityError, DataIntegrityProofSuite
from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
from openvc.proof.di_jcs import EcdsaJcsProofSuite, EddsaJcsProofSuite
from openvc.proof.ecdsa_sd import (
    EcdsaSdProofSuite,
    decode_derived_proof,
    encode_derived_proof,
)
from openvc.proof.errors import (
    ClaimsInvalid,
    KeyResolutionError,
    MalformedToken,
    ProofMalformed,
    SignatureInvalid,
)
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.proof.vp_jwt import VpJwtProofSuite
from openvc.resolvers import default_status_list_resolver, default_status_list_resolver_async
from openvc.verify import KeyResolutionFailed

V2 = "https://www.w3.org/ns/credentials/v2"
HI, LO = "\ud800", "\udc00"                       # a lone high / low UTF-16 surrogate
SURROGATES = [pytest.param(HI, id="high"), pytest.param(LO, id="low")]
NONCE, CLIENT_ID = "n-1", "x509_san_dns:client.example.org"
FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _wire(obj):
    """What arrives on the wire: the object as JSON, which escapes a lone surrogate as
    ``\\ud800``, read back through the production loader (which accepts the escape)."""
    text = json.dumps(obj)
    assert "\\ud800" in text or "\\udc00" in text, "the fixture lost its surrogate"
    return _json.loads(text)


def _did_key_ed25519():
    sk = ed25519.Ed25519PrivateKey.generate()
    mb = encode_multibase(bytes([0xED, 0x01]) + Ed25519SigningKey(sk, "_").public_key_raw())
    return Ed25519SigningKey(sk, f"did:key:{mb}#{mb}"), f"did:key:{mb}"


def _did_key_p256():
    sk = ec.generate_private_key(ec.SECP256R1())
    mb = encode_multibase(bytes([0x80, 0x24]) + P256SigningKey(sk, "_").public_key_raw())
    return P256SigningKey(sk, f"did:key:{mb}#{mb}"), f"did:key:{mb}"


ED, ED_DID = _did_key_ed25519()                    # issuer of the eddsa-* suites
P256, P256_DID = _did_key_p256()                   # issuer of the ecdsa-* suites, ES256
HOLDER, HOLDER_DID = _did_key_ed25519()


def _credential(issuer: str) -> dict:
    """A document whose subject is a NAMED node (``credentialSubject.id``)."""
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": issuer,
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:alice", "name": "Alice",
                                  "description": "d"}}


def _batch_error_classes(results) -> list:
    return [type(r.error) if r.error is not None else None for r in results]


def _assert_isolated(results, error_class) -> None:
    """The hostile item carries the typed error and the good one, after it, still verified."""
    assert len(results) == 2
    assert type(results[0].error) is error_class and results[0].result is None
    assert results[1].ok and results[1].error is None and results[1].result is not None


# --------------------------------------------------------------------------- #
# 0. the helper itself
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("s", SURROGATES)
@pytest.mark.parametrize("make", [lambda s: s + "ab", lambda s: "a" + s + "b",
                                  lambda s: "ab" + s], ids=["start", "middle", "end"])
def test_utf8_helper_raises_the_callers_class_naming_position_not_text(s, make):
    text = make(s) + "SECRET-TAIL" * 50
    with pytest.raises(DataIntegrityError) as exc:
        _json.utf8(text, error=DataIntegrityError, what="the thing")
    assert type(exc.value) is DataIntegrityError
    message = str(exc.value)
    assert message.startswith("the thing holds a lone UTF-16 surrogate (U+D8" if s == HI
                              else "the thing holds a lone UTF-16 surrogate (U+DC")
    assert "index" in message
    assert "SECRET-TAIL" not in message and len(message) < 120    # bounded, never the text
    assert type(exc.value.__cause__) is UnicodeEncodeError


def test_utf8_helper_never_repairs_and_keeps_every_valid_string():
    assert _json.utf8("Alice \U0001F600 é", error=ValueError, what="x") == \
        "Alice \U0001F600 é".encode("utf-8")
    assert _json.utf8("", error=ValueError, what="x") == b""
    # the surrogate PAIR written as two JSON escapes is one code point once parsed
    assert _json.loads('"\\ud83d\\ude00"') == "\U0001F600"


# --------------------------------------------------------------------------- #
# 1. the RDF suites: DataIntegrityProofSuite._canonize, shared by both
# --------------------------------------------------------------------------- #

RDF_SUITES = {
    "eddsa-rdfc-2022": (DataIntegrityProofSuite, ED, ED_DID),
    "ecdsa-rdfc-2019": (EcdsaRdfcProofSuite, P256, P256_DID),
}


def _signed(suite: str) -> dict:
    cls, key, did = RDF_SUITES[suite]
    return cls().add_proof(_credential(did), signing_key=key, verification_method=key.kid)


# Every placement is on a NAMED node, so pyld never hashes (and so never types) it.
def _value_start(d, s):
    d["credentialSubject"]["name"] = s + "Alice"


def _value_middle(d, s):
    d["credentialSubject"]["name"] = "Al" + s + "ice"


def _value_end(d, s):
    d["credentialSubject"]["name"] = "Alice" + s


def _array_value(d, s):
    d["credentialSubject"]["name"] = ["Alice", "Bob" + s]


def _nested_value_object(d, s):
    d["credentialSubject"]["name"] = {"@value": "Alice" + s}


def _property_key(d, s):
    d["credentialSubject"]["https://example.org/p" + s] = "v"


def _credential_with_id(d, s):
    d["id"] = "urn:uuid:0001"
    d["name"] = "Credential" + s


def _nested_issuer_node(d, s):
    d["issuer"] = {"id": d["issuer"], "name": "Issuer" + s}


def _type_entry(d, s):
    d["id"] = "urn:uuid:0002"                      # an id makes the credential a named node
    d["type"] = ["VerifiableCredential", "Example" + s]


PLACEMENTS = {
    "value-start": _value_start, "value-middle": _value_middle, "value-end": _value_end,
    "array-value": _array_value, "nested-value-object": _nested_value_object,
    "property-key": _property_key, "credential-with-id": _credential_with_id,
    "nested-issuer-node": _nested_issuer_node, "type-entry": _type_entry,
}


def _pyld_keeps_a_surrogate_type_iri() -> bool:
    """pyld 3.x writes a ``type`` IRI holding a surrogate into the N-Quads, where it reaches
    the encode. pyld 2.0.4 (the CI floor leg) drops the IRI instead, so it never gets there
    and openvc's context validation refuses the document as ``ProofMalformed``. Both were
    typed before this change; the ``type-entry`` placement is only a negative on 3.x.

    Also the module's pyld guard: like the other Data Integrity test files it skips whole
    without the ``[data-integrity]`` extra (every CI leg installs it)."""
    jsonld = pytest.importorskip("pyld.jsonld")

    from openvc.proof.contexts import document_loader
    quads = jsonld.normalize(
        {"@context": [V2], "id": "urn:x", "type": ["VerifiableCredential", "Example\ud800"]},
        {"algorithm": "URDNA2015", "format": "application/n-quads",
         "documentLoader": document_loader(None)})
    return "\ud800" in quads


KEEPS_TYPE_IRI = _pyld_keeps_a_surrogate_type_iri()
NEEDS_PYLD_3 = pytest.mark.skipif(
    not KEEPS_TYPE_IRI, reason="pyld < 3 drops a type IRI holding a surrogate (see the helper)")


def _placements(table) -> list:
    return [pytest.param(name, marks=NEEDS_PYLD_3) if name == "type-entry" else name
            for name in table]


PLACEMENT_PARAMS = pytest.mark.parametrize("placement", _placements(PLACEMENTS))
SUITE_PARAMS = pytest.mark.parametrize("suite", list(RDF_SUITES))
# "no signature from anyone" vs a real signature copied from the untampered credential
SIGNATURE_PARAMS = pytest.mark.parametrize("signature", ["z1111", "stale-real"])


def _tampered(signed: dict, placement: str, s: str, signature: str) -> dict:
    doc = copy.deepcopy(signed)
    PLACEMENTS[placement](doc, s)
    if signature == "z1111":
        doc["proof"]["proofValue"] = "z1111"
    return doc


def test_the_good_rdf_credentials_verify():
    for suite in RDF_SUITES:
        assert verify_credential(_signed(suite)).issuer == RDF_SUITES[suite][2]


@SUITE_PARAMS
@PLACEMENT_PARAMS
@SIGNATURE_PARAMS
def test_rdf_control_without_a_surrogate_reaches_the_signature_check(
        suite, placement, signature):
    # the same shape with a benign string: canonicalisation, key resolution and context
    # validation all pass and the signature is what refuses it. A negative below therefore
    # cannot be passing on some other class that fires first.
    doc = _tampered(_signed(suite), placement, "X", signature)
    with pytest.raises(SignatureInvalid) as exc:
        verify_credential(doc)
    assert type(exc.value) is SignatureInvalid


@SUITE_PARAMS
@PLACEMENT_PARAMS
@SIGNATURE_PARAMS
@pytest.mark.parametrize("s", SURROGATES)
def test_rdf_named_node_surrogate_raises_data_integrity_error(suite, placement, signature, s):
    hostile = _wire(_tampered(_signed(suite), placement, s, signature))
    with pytest.raises(DataIntegrityError) as exc:
        verify_credential(hostile)
    assert type(exc.value) is DataIntegrityError
    assert "lone UTF-16 surrogate" in str(exc.value)          # the new guard, not pyld's own


@SUITE_PARAMS
@pytest.mark.parametrize("s", SURROGATES)
def test_rdf_blank_node_shape_was_already_typed_and_stays_so(suite, s):
    # the control the issue asks for: a subject WITHOUT an id is a blank node, hashed by pyld
    # inside the guarded normalize, so this passed on main and proves nothing about the
    # encode after it. It is pinned so the two shapes are known to agree.
    doc = _signed(suite)
    doc["credentialSubject"].pop("id")
    doc["credentialSubject"]["name"] = "Alice" + s
    doc["proof"]["proofValue"] = "z1111"
    with pytest.raises(DataIntegrityError) as exc:
        verify_credential(_wire(doc))
    assert type(exc.value) is DataIntegrityError


@pytest.mark.skipif(KEEPS_TYPE_IRI, reason="pyld 3.x: the type-entry placement is a negative")
@SUITE_PARAMS
@pytest.mark.parametrize("s", SURROGATES)
def test_rdf_floor_pyld_drops_a_surrogate_type_iri_and_the_context_check_types_it(suite, s):
    # the CI floor leg (pyld 2.0.4): nothing reaches the encode, and the document is still
    # refused with a typed error (never signed, never accepted)
    cls, key, did = RDF_SUITES[suite]
    doc = _credential(did)
    _type_entry(doc, s)
    with pytest.raises(ProofMalformed, match="type the signed dataset drops") as exc:
        cls().add_proof(doc, signing_key=key, verification_method=key.kid)
    assert type(exc.value) is ProofMalformed


@SUITE_PARAMS
@pytest.mark.parametrize("s", SURROGATES)
def test_rdf_other_entry_points_raise_data_integrity_error(suite, s):
    cls, key, _ = RDF_SUITES[suite]
    for placement in ("value-middle", "property-key", "nested-issuer-node"):
        for signature in ("z1111", "stale-real"):
            hostile = _wire(_tampered(_signed(suite), placement, s, signature))
            with pytest.raises(DataIntegrityError) as exc:
                cls().verify(hostile, public_key_jwk=key.public_jwk())
            assert type(exc.value) is DataIntegrityError
            with pytest.raises(DataIntegrityError) as aexc:
                asyncio.run(verify_credential_async(hostile))
            assert type(aexc.value) is DataIntegrityError


@SUITE_PARAMS
@PLACEMENT_PARAMS
@pytest.mark.parametrize("s", SURROGATES)
def test_rdf_batch_isolates_the_hostile_item(suite, placement, s):
    good = _signed(suite)
    hostile = _wire(_tampered(good, placement, s, "z1111"))
    _assert_isolated(verify_many([hostile, good]), DataIntegrityError)
    _assert_isolated(asyncio.run(verify_many_async([hostile, good])), DataIntegrityError)


@SUITE_PARAMS
@pytest.mark.parametrize("s", SURROGATES)
def test_rdf_issuer_side_add_proof_raises_data_integrity_error(suite, s):
    cls, key, did = RDF_SUITES[suite]
    for placement in ("value-start", "value-middle", "value-end", "property-key",
                      "nested-issuer-node"):
        doc = _credential(did)
        PLACEMENTS[placement](doc, s)
        with pytest.raises(DataIntegrityError) as exc:
            cls().add_proof(doc, signing_key=key, verification_method=key.kid)
        assert type(exc.value) is DataIntegrityError


# --------------------------------------------------------------------------- #
# 1a / 1b. the same canonicaliser behind verify_vp_token and the VP-JWT
# --------------------------------------------------------------------------- #

def _holder_vc() -> dict:
    """A good eddsa-rdfc-2022 credential about the holder (OpenID4VP binds subject to holder)."""
    doc = _credential(ED_DID)
    doc["credentialSubject"]["id"] = HOLDER_DID
    return DataIntegrityProofSuite().add_proof(doc, signing_key=ED, verification_method=ED.kid)


def _ldp_vp(name: str, signature: str) -> dict:
    """A VP with an ``id`` (a named node) and a VP-level literal, signed by the holder, then
    tampered: the literal changes after the proof, as a hostile holder would send it."""
    vc = _holder_vc()
    vp = {"@context": [V2], "id": "urn:vp:1", "type": ["VerifiablePresentation"],
          "holder": HOLDER_DID, "name": "P", "verifiableCredential": [vc]}
    signed = DataIntegrityProofSuite().add_proof(
        vp, signing_key=HOLDER, verification_method=HOLDER.kid,
        proof_purpose="authentication", challenge=NONCE, domain=CLIENT_ID)
    signed["name"] = name
    if signature == "z1111":
        signed["proof"]["proofValue"] = "z1111"
    return signed


def _vvt_ldp(vp):
    return verify_vp_token(
        {"q": [vp]}, dcql_query={"credentials": [{"id": "q", "format": "ldp_vc"}]},
        nonce=NONCE, client_id=CLIENT_ID)


def test_ldp_vp_good_verifies():
    assert _vvt_ldp(_ldp_vp("P", "stale-real")) is not None


@SIGNATURE_PARAMS
def test_ldp_vp_control_without_a_surrogate_reaches_the_signature_check(signature):
    with pytest.raises(SignatureInvalid) as exc:
        _vvt_ldp(_ldp_vp("PX", signature))
    assert type(exc.value) is SignatureInvalid


@SIGNATURE_PARAMS
@pytest.mark.parametrize("name", [lambda s: s + "P", lambda s: "P" + s + "Q",
                                  lambda s: "P" + s], ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_ldp_vp_literal_surrogate_raises_data_integrity_error(signature, name, s):
    hostile = _wire(_ldp_vp(name(s), signature))
    with pytest.raises(DataIntegrityError) as exc:
        _vvt_ldp(hostile)
    assert type(exc.value) is DataIntegrityError
    # a caller that presents several VPs and catches OpenvcError per presentation isolates it
    survivors = []
    for vp in (hostile, _ldp_vp("P", "stale-real")):
        try:
            survivors.append(_vvt_ldp(vp))
        except OpenvcError:
            survivors.append(None)
    assert survivors[0] is None and survivors[1] is not None


def _vp_jwt_carrying(vc: dict) -> str:
    return VpJwtProofSuite().sign([vc], holder_key=HOLDER, audience=CLIENT_ID, nonce=NONCE)


@SIGNATURE_PARAMS
@pytest.mark.parametrize("placement", ["value-start", "value-middle", "value-end",
                                       "property-key", "nested-issuer-node"])
@pytest.mark.parametrize("s", SURROGATES)
def test_vp_jwt_carrying_an_ldp_vc_raises_data_integrity_error(signature, placement, s):
    # the holder signs the VP-JWT with its own key, so it may carry whatever it likes
    vp_jwt = _vp_jwt_carrying(_wire(_tampered(_holder_vc(), placement, s, signature)))
    with pytest.raises(DataIntegrityError) as exc:
        VpJwtProofSuite().verify(
            vp_jwt, holder_key_jwk=HOLDER.public_jwk(), audience=CLIENT_ID, nonce=NONCE)
    assert type(exc.value) is DataIntegrityError
    with pytest.raises(DataIntegrityError) as vexc:
        verify_vp_token(
            {"q": [vp_jwt]},
            dcql_query={"credentials": [{"id": "q", "format": "jwt_vc_json"}]},
            nonce=NONCE, client_id=CLIENT_ID)
    assert type(vexc.value) is DataIntegrityError


def test_vp_jwt_control_without_a_surrogate_reaches_the_embedded_signature_check():
    vp_jwt = _vp_jwt_carrying(_tampered(_holder_vc(), "value-end", "X", "z1111"))
    with pytest.raises(SignatureInvalid) as exc:
        VpJwtProofSuite().verify(
            vp_jwt, holder_key_jwk=HOLDER.public_jwk(), audience=CLIENT_ID, nonce=NONCE)
    assert type(exc.value) is SignatureInvalid


# --------------------------------------------------------------------------- #
# 1c. the second hop: a fetched status-list credential reaches the same canonicaliser
# --------------------------------------------------------------------------- #

STATUS_URL = "https://status.example/list/1"


def _status_list(encoded: str, signature: str) -> str:
    """The text a hostile status server serves: an eddsa-rdfc-2022 list credential whose
    subject is a named node (``<url>#list``), tampered after signing."""
    sl = {"@context": [V2], "id": STATUS_URL,
          "type": ["VerifiableCredential", "BitstringStatusListCredential"], "issuer": ED_DID,
          "credentialSubject": {"id": STATUS_URL + "#list", "type": "BitstringStatusList",
                                "statusPurpose": "revocation", "encodedList": "uH4sIAAAAAAAA"}}
    signed = DataIntegrityProofSuite().add_proof(
        sl, signing_key=ED, verification_method=ED.kid)
    signed["credentialSubject"]["encodedList"] = encoded
    if signature == "z1111":
        signed["proof"]["proofValue"] = "z1111"
    return json.dumps(signed)                 # json.dumps puts the \ud800 escape on the wire


def _outer_vc_jwt() -> str:
    """A VC-JWT the ATTACKER signs with a key of their own (any did:key is an issuer)."""
    return VcJwtProofSuite().sign({
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
        "credentialSubject": {"id": "did:example:holder"},
        "credentialStatus": {"id": STATUS_URL + "#7", "type": "BitstringStatusListEntry",
                             "statusPurpose": "revocation", "statusListIndex": "7",
                             "statusListCredential": STATUS_URL}}, signing_key=P256)


def _plain_vc_jwt() -> str:
    return VcJwtProofSuite().sign({
        "@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
        "credentialSubject": {"id": "did:example:holder"}}, signing_key=P256)


def test_status_list_control_without_a_surrogate_reaches_the_list_signature_check():
    resolver = default_status_list_resolver(
        fetch=lambda url: _status_list("uH4sIAAAAAAAAX", "z1111"))
    with pytest.raises(SignatureInvalid) as exc:
        verify_credential(_outer_vc_jwt(), resolve_status_list=resolver)
    assert type(exc.value) is SignatureInvalid


@SIGNATURE_PARAMS
@pytest.mark.parametrize("encoded", [lambda s: s + "uH4sI", lambda s: "uH4" + s + "sI",
                                     lambda s: "uH4sI" + s], ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_status_list_second_hop_raises_data_integrity_error(signature, encoded, s):
    text = _status_list(encoded(s), signature)
    assert "\\ud800" in text.lower() or "\\udc00" in text.lower()
    resolver = default_status_list_resolver(fetch=lambda url: text)
    with pytest.raises(DataIntegrityError) as exc:
        verify_credential(_outer_vc_jwt(), resolve_status_list=resolver)
    assert type(exc.value) is DataIntegrityError

    _assert_isolated(
        verify_many([_outer_vc_jwt(), _plain_vc_jwt()], resolve_status_list=resolver),
        DataIntegrityError)

    async def afetch(url):
        return text
    aresolver = default_status_list_resolver_async(fetch=afetch)
    with pytest.raises(DataIntegrityError) as aexc:
        asyncio.run(verify_credential_async(_outer_vc_jwt(), resolve_status_list=aresolver))
    assert type(aexc.value) is DataIntegrityError
    _assert_isolated(
        asyncio.run(verify_many_async([_outer_vc_jwt(), _plain_vc_jwt()],
                                      resolve_status_list=aresolver)),
        DataIntegrityError)


# --------------------------------------------------------------------------- #
# 2 / 3 / 3a. ecdsa-sd-2023
# --------------------------------------------------------------------------- #

SD = EcdsaSdProofSuite()


def _sd_credential() -> dict:
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:alice", "name": "Alice",
                                  "description": "d"}}


def _sd_base(mandatory=("/issuer",)) -> dict:
    return SD.add_base_proof(_sd_credential(), signing_key=P256, verification_method=P256.kid,
                             mandatory_pointers=list(mandatory))


def _sd_derived() -> dict:
    return SD.derive_proof(_sd_base(), selective_pointers=["/credentialSubject/name"])


def _fabricated(derived: dict, base_signature: bytes = bytes(64), n_mandatory: int = 16) -> dict:
    """A derived proof an attacker writes without the issuer's key: a made-up base signature
    and ``mandatory_indexes`` of their choosing (every statement mandatory)."""
    parsed = decode_derived_proof(derived["proof"]["proofValue"])
    doc = copy.deepcopy(derived)
    doc["proof"]["proofValue"] = encode_derived_proof(
        base_signature=base_signature, public_key=parsed["public_key"], signatures=[],
        label_map=parsed["label_map"], mandatory_indexes=list(range(n_mandatory)))
    return doc


SD_PLACEMENTS = {
    "value-start": _value_start, "value-middle": _value_middle, "value-end": _value_end,
    "array-value": _array_value, "nested-value-object": _nested_value_object,
    "property-key": _property_key, "nested-issuer-node": _nested_issuer_node,
    "type-entry": _type_entry,
}


def test_ecdsa_sd_good_derived_credential_verifies():
    assert verify_credential(_sd_derived()).issuer == P256_DID


@pytest.mark.parametrize("placement", _placements(SD_PLACEMENTS))
def test_ecdsa_sd_row2_control_reaches_the_base_signature_check(placement):
    doc = _fabricated(_sd_derived())
    SD_PLACEMENTS[placement](doc, "X")
    with pytest.raises(SignatureInvalid) as exc:
        verify_credential(doc)
    assert type(exc.value) is SignatureInvalid


@pytest.mark.parametrize("placement", _placements(SD_PLACEMENTS))
@pytest.mark.parametrize("s", SURROGATES)
def test_ecdsa_sd_row2_attacker_chosen_mandatory_indexes_raise_proof_malformed(placement, s):
    # no key: base_signature is 64 zero bytes, and the hash of the mandatory statements is
    # computed (over the holder-chosen mandatory_indexes) before that signature is checked
    doc = _fabricated(_sd_derived())
    SD_PLACEMENTS[placement](doc, s)
    hostile = _wire(doc)
    with pytest.raises(ProofMalformed) as exc:
        verify_credential(hostile)
    assert type(exc.value) is ProofMalformed
    assert "lone UTF-16 surrogate" in str(exc.value)
    with pytest.raises(ProofMalformed) as sexc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(sexc.value) is ProofMalformed
    with pytest.raises(ProofMalformed) as aexc:
        asyncio.run(verify_credential_async(hostile))
    assert type(aexc.value) is ProofMalformed
    good = _sd_derived()
    _assert_isolated(verify_many([hostile, good]), ProofMalformed)
    _assert_isolated(asyncio.run(verify_many_async([hostile, good])), ProofMalformed)


@pytest.mark.parametrize("edit", [_value_start, _value_middle, _value_end],
                         ids=["start", "middle", "end"])
def test_ecdsa_sd_row3_control_reaches_the_statement_signature_check(edit):
    # self-issued, derived honestly, then a non-mandatory disclosed statement is edited: the
    # base signature still verifies, so it is the per-statement signature that refuses it
    doc = _sd_derived()
    edit(doc, "X")
    with pytest.raises(SignatureInvalid, match="disclosed statement") as exc:
        verify_credential(doc)
    assert type(exc.value) is SignatureInvalid


@pytest.mark.parametrize("edit", [_value_start, _value_middle, _value_end],
                         ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_ecdsa_sd_row3_edited_disclosed_statement_raises_proof_malformed(edit, s):
    doc = _sd_derived()
    edit(doc, s)
    hostile = _wire(doc)
    with pytest.raises(ProofMalformed) as exc:
        verify_credential(hostile)
    assert type(exc.value) is ProofMalformed
    with pytest.raises(ProofMalformed) as sexc:
        SD.verify(hostile, public_key_jwk=P256.public_jwk())
    assert type(sexc.value) is ProofMalformed
    good = _sd_derived()
    _assert_isolated(verify_many([hostile, good]), ProofMalformed)
    _assert_isolated(asyncio.run(verify_many_async([hostile, good])), ProofMalformed)


@pytest.mark.parametrize("member", ["domain", "challenge"])
@pytest.mark.parametrize("s", SURROGATES)
def test_ecdsa_sd_proof_with_an_id_is_a_named_node_in_the_proof_configuration(member, s):
    # a proof with an ``id`` is a named node, so pyld does not hash its literals either: the
    # proof configuration is the second N-Quads string that reaches an encode. (Without the
    # ``id`` the proof is a blank node and pyld types the failure itself.)
    control = _sd_derived()
    control["proof"].update({"id": "urn:proof:1", member: "benign"})
    with pytest.raises(SignatureInvalid) as cexc:
        verify_credential(control)
    assert type(cexc.value) is SignatureInvalid
    doc = _sd_derived()
    doc["proof"].update({"id": "urn:proof:1", member: "x" + s})
    with pytest.raises(ProofMalformed, match="proof configuration N-Quads") as exc:
        verify_credential(_wire(doc))
    assert type(exc.value) is ProofMalformed


@pytest.mark.parametrize("s", SURROGATES)
def test_ecdsa_sd_blank_node_shapes_were_already_typed_and_stay_so(s):
    derived = _sd_derived()
    anonymous = copy.deepcopy(derived)
    anonymous["credentialSubject"].pop("id")
    anonymous["credentialSubject"]["name"] = "Alice" + s
    with pytest.raises(ProofMalformed) as exc:
        verify_credential(_wire(anonymous))
    assert type(exc.value) is ProofMalformed
    created = copy.deepcopy(derived)
    created["proof"]["created"] = "2024" + s
    with pytest.raises(ProofMalformed) as cexc:
        verify_credential(_wire(created))
    assert type(cexc.value) is ProofMalformed


@pytest.mark.parametrize("pointers", [("/issuer",), ("/credentialSubject/name",)],
                         ids=["non-mandatory-statement", "mandatory-statement"])
@pytest.mark.parametrize("edit", [_value_start, _value_middle, _value_end, _property_key],
                         ids=["start", "middle", "end", "key"])
@pytest.mark.parametrize("s", SURROGATES)
def test_ecdsa_sd_issuer_side_add_base_proof_raises_proof_malformed(pointers, edit, s):
    doc = _sd_credential()
    edit(doc, s)
    with pytest.raises(ProofMalformed) as exc:
        SD.add_base_proof(doc, signing_key=P256, verification_method=P256.kid,
                          mandatory_pointers=list(pointers))
    assert type(exc.value) is ProofMalformed
    assert "lone UTF-16 surrogate" in str(exc.value)


# --------------------------------------------------------------------------- #
# 4. did:webvh pre-rotation
# --------------------------------------------------------------------------- #

def _webvh_entries() -> list[dict]:
    path = FIXTURES / "didwebvh" / "pre-rotation-consume.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


WEBVH_DID = _webvh_entries()[-1]["state"]["id"]


def _webvh_log(update_key) -> str:
    """The recorded pre-rotation log with entry 2's ``updateKeys`` replaced. Entry 1 commits
    to the next key (``nextKeyHashes``), so entry 2's keys are hashed to check the
    commitment, and that happens before entry 2's hash chain or proof is looked at."""
    entries = _webvh_entries()
    assert entries[0]["parameters"]["nextKeyHashes"]
    entries[1]["parameters"]["updateKeys"] = [update_key]
    return "\n".join(json.dumps(e) for e in entries) + "\n"


def _unsigned_jose(did: str) -> str:
    def seg(obj):
        import base64
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'EdDSA', 'kid': did + '#k'})}.{seg({'iss': did, 'vc': {}})}.AAAA"


def _unsigned_di(did: str) -> dict:
    return {"@context": [V2], "type": ["VerifiableCredential"], "issuer": did,
            "credentialSubject": {"id": "did:example:x"},
            "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                      "verificationMethod": did + "#k", "proofPurpose": "assertionMethod",
                      "proofValue": "z1111"}}


def _webvh_registry(text: str) -> DidResolverRegistry:
    return DidResolverRegistry([DidKeyResolver(), DidWebvhResolver(fetch=lambda url: text)])


def _webvh_async_registry(text: str) -> AsyncDidResolverRegistry:
    async def fetch(url):
        return text
    return AsyncDidResolverRegistry(
        [as_async_resolver(DidKeyResolver()), AsyncDidWebvhResolver(fetch=fetch)])


def test_webvh_recorded_pre_rotation_log_resolves():
    text = "\n".join(json.dumps(e) for e in _webvh_entries()) + "\n"
    assert DidWebvhResolver(fetch=lambda url: text).resolve(WEBVH_DID).id == WEBVH_DID


def test_webvh_control_a_benign_non_committed_key_fails_the_commitment_check():
    # ASCII, so the new guard passes it and the pre-rotation commitment is what refuses it
    with pytest.raises(DidWebvhError, match="not a pre-rotated key") as exc:
        DidWebvhResolver(fetch=lambda url: _webvh_log("z6MkX")).resolve(WEBVH_DID)
    assert type(exc.value) is DidWebvhError


WEBVH_KEYS = [lambda s: s + "z6Mk", lambda s: "z6" + s + "Mk", lambda s: "z6Mk" + s]


@pytest.mark.parametrize("key", WEBVH_KEYS, ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_webvh_update_key_surrogate_raises_did_webvh_error(key, s):
    text = _webvh_log(key(s))
    with pytest.raises(DidWebvhError, match="ASCII multikey") as exc:
        DidWebvhResolver(fetch=lambda url: text).resolve(WEBVH_DID)
    assert type(exc.value) is DidWebvhError

    async def fetch(url):
        return text
    with pytest.raises(DidWebvhError, match="ASCII multikey") as aexc:
        asyncio.run(AsyncDidWebvhResolver(fetch=fetch).resolve(WEBVH_DID))
    assert type(aexc.value) is DidWebvhError


@pytest.mark.parametrize("key", WEBVH_KEYS, ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_webvh_update_key_surrogate_through_the_pipeline(key, s):
    text = _webvh_log(key(s))
    registry, aregistry = _webvh_registry(text), _webvh_async_registry(text)
    # JOSE lane (iss): the pipeline maps a resolution failure to KeyResolutionFailed
    jose = _unsigned_jose(WEBVH_DID)
    with pytest.raises(KeyResolutionFailed) as exc:
        verify_credential(jose, resolver=registry)
    assert type(exc.value) is KeyResolutionFailed
    assert type(exc.value.__cause__) is DidWebvhError
    with pytest.raises(KeyResolutionFailed) as aexc:
        asyncio.run(verify_credential_async(jose, resolver=aregistry))
    assert type(aexc.value) is KeyResolutionFailed
    # Data Integrity lane (verificationMethod): KeyResolutionError, sync and async alike
    # (#283); it is a KeyResolutionFailed too
    di = _unsigned_di(WEBVH_DID)
    with pytest.raises(KeyResolutionError) as dexc:
        verify_credential(di, resolver=registry)
    assert type(dexc.value) is KeyResolutionError
    assert isinstance(dexc.value, KeyResolutionFailed)
    assert type(dexc.value.__cause__) is DidWebvhError
    with pytest.raises(KeyResolutionError) as adexc:
        asyncio.run(verify_credential_async(di, resolver=aregistry))
    assert type(adexc.value) is KeyResolutionError
    assert isinstance(adexc.value, KeyResolutionFailed)
    # batch isolation: the hostile item, then a good did:key credential that still verifies
    good = _plain_vc_jwt()
    _assert_isolated(verify_many([jose, good], resolver=registry), KeyResolutionFailed)
    _assert_isolated(verify_many([di, good], resolver=registry), KeyResolutionError)
    _assert_isolated(asyncio.run(verify_many_async([jose, good], resolver=aregistry)),
                     KeyResolutionFailed)
    _assert_isolated(asyncio.run(verify_many_async([di, good], resolver=aregistry)),
                     KeyResolutionError)


# --------------------------------------------------------------------------- #
# 5 / 6 / 7 / 8. OpenID4VCI and the JWK thumbprint
# --------------------------------------------------------------------------- #

CI = "https://issuer.example"
PROOF_KEY = P256.public_jwk()


def _proof_jwt(**header_extra) -> str:
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": PROOF_KEY, **header_extra}
    return sign_compact(header, {"aud": CI, "iat": int(time.time()), "nonce": "n"},
                        signing_key=P256)


def _unsigned_proof(header: dict) -> str:
    """A key proof with no valid signature. The header is JSON inside a base64url segment, so
    a surrogate in it is a ``\\ud800`` escape the JWS parser reads back."""
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg(header)}.{seg({'aud': CI, 'iat': int(time.time())})}.AAAA"


def _has_escape(text: str) -> bool:
    return "\\ud800" in text or "\\udc00" in text


def _request(proof: str) -> dict:
    return {"credential_configuration_id": "x", "proofs": {"jwt": [proof]}}


def _verify_proofs(body):
    return verify_credential_request_proofs(
        body, credential_issuer=CI, check_nonce=lambda n: True)


def _attestation(keys: list) -> str:
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return (f"{seg({'alg': 'ES256', 'typ': 'key-attestation+jwt'})}."
            f"{seg({'iat': int(time.time()), 'attested_keys': keys})}.AAAA")


COMPACT = [lambda jws, s: s + jws, lambda jws, s: jws[:20] + s + jws[20:],
           lambda jws, s: jws + s]


def test_openid4vci_good_proof_is_accepted():
    assert parse_credential_request(_request(_proof_jwt())).proofs
    assert _verify_proofs(_request(_proof_jwt()))


@pytest.mark.parametrize("place", COMPACT, ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_row5_parse_credential_request_proof_surrogate(place, s):
    jws = _proof_jwt()
    body = _request(place(jws, s))
    for given in (_wire(body), json.dumps(body)):               # an object, and the JSON string
        with pytest.raises(CredentialRequestMalformed) as exc:
            parse_credential_request(given)
        assert type(exc.value) is CredentialRequestMalformed
        with pytest.raises(CredentialRequestMalformed) as vexc:
            _verify_proofs(given)
        assert type(vexc.value) is CredentialRequestMalformed
    # the escape is really on the wire in the string form
    assert "\\ud800" in json.dumps(body).lower() or "\\udc00" in json.dumps(body).lower()


@pytest.mark.parametrize("s", SURROGATES)
def test_row5_another_proof_type_with_a_string_entry_is_refused_too(s):
    body = {"credential_configuration_id": "x", "proofs": {"attestation": ["a" + s]}}
    with pytest.raises(CredentialRequestMalformed) as exc:
        parse_credential_request(_wire(body))
    assert type(exc.value) is CredentialRequestMalformed


def test_row5_a_non_ascii_proof_is_not_a_compact_jws():
    # a compact JWS is base64url and dots. This is the one change for input that was not a
    # surrogate: it used to pass this parse and fail later in parse_compact.
    with pytest.raises(CredentialRequestMalformed, match="ASCII") as exc:
        parse_credential_request(_request("eyJé.e30.AAAA"))
    assert type(exc.value) is CredentialRequestMalformed


@pytest.mark.parametrize("place", COMPACT, ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_row6_peek_proof_header_surrogate(place, s):
    assert peek_proof_header(_proof_jwt())["alg"] == "ES256"             # the control
    with pytest.raises(MalformedToken) as exc:
        peek_proof_header(place(_proof_jwt(), s))
    assert type(exc.value) is MalformedToken


@pytest.mark.parametrize("place", COMPACT, ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_row7_peek_key_attestation_surrogate(place, s):
    attestation = _attestation([PROOF_KEY])
    assert peek_key_attestation(attestation).attested_keys                 # the control
    with pytest.raises(MalformedToken) as exc:
        peek_key_attestation(place(attestation, s))
    assert type(exc.value) is MalformedToken


@pytest.mark.parametrize("s", SURROGATES)
def test_row7_key_attestation_header_string_with_a_surrogate(s):
    good_header_proof = _unsigned_proof({"typ": "openid4vci-proof+jwt", "alg": "ES256",
                                         "jwk": PROOF_KEY, "key_attestation": "eyJ"})
    # the control: the same shape with a benign string fails inside the attestation parse
    with pytest.raises(MalformedToken) as cexc:
        _verify_proofs(_request(good_header_proof))
    assert type(cexc.value) is MalformedToken and "ASCII" not in str(cexc.value)
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": PROOF_KEY,
              "key_attestation": "eyJ" + s}
    assert _has_escape(json.dumps(header))
    hostile = _unsigned_proof(header)
    for given in (_request(hostile), json.dumps(_request(hostile))):
        with pytest.raises(MalformedToken, match="ASCII compact JWS") as exc:
            _verify_proofs(given)
        assert type(exc.value) is MalformedToken


JWK_MEMBERS = [
    ({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}, "x"),
    ({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}, "x"),
    ({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}, "y"),
    ({"kty": "RSA", "n": "AAAA", "e": "AQAB"}, "n"),
    ({"kty": "RSA", "n": "AAAA", "e": "AQAB"}, "e"),
    ({"kty": "oct", "k": "AAAA"}, "k"),
]


@pytest.mark.parametrize("jwk,member", JWK_MEMBERS,
                         ids=[f"{j['kty']}-{m}" for j, m in JWK_MEMBERS])
@pytest.mark.parametrize("place", [lambda v, s: s + v, lambda v, s: v[:2] + s + v[2:],
                                   lambda v, s: v + s], ids=["start", "middle", "end"])
@pytest.mark.parametrize("s", SURROGATES)
def test_row8_jwk_thumbprint_surrogate_raises_invalid_key(jwk, member, place, s):
    assert jwk_thumbprint(jwk)                                          # the control
    hostile = dict(jwk, **{member: place(jwk[member], s)})
    for call in (jwk_thumbprint, jwk_thumbprint_bytes):
        with pytest.raises(InvalidKey) as exc:
            call(hostile)
        assert type(exc.value) is InvalidKey
        assert repr(member) in str(exc.value) and "AAAA" not in str(exc.value)


def test_row8_a_valid_non_bmp_member_still_has_a_thumbprint():
    # the digest covers the UTF-8 of the member, unchanged for a valid character
    import hashlib
    jwk = {"kty": "oct", "k": "k\U0001F600"}
    expected = hashlib.sha256(
        json.dumps({"k": "k\U0001F600", "kty": "oct"}, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).digest()
    assert jwk_thumbprint_bytes(jwk) == expected


@pytest.mark.parametrize("member", ["x", "y"])
@pytest.mark.parametrize("s", SURROGATES)
def test_row8_header_jwk_and_attested_key_before_any_signature_check(member, s):
    # the proof header's jwk: read for its thumbprint before the signature is verified. The
    # control (a benign suffix) gets past the thumbprint and fails at the signature.
    benign = dict(PROOF_KEY, **{member: PROOF_KEY[member] + "A"})
    with pytest.raises(SignatureInvalid) as cexc:
        _verify_proofs(_request(_unsigned_proof(
            {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": benign})))
    assert type(cexc.value) is SignatureInvalid
    jwk = dict(PROOF_KEY, **{member: PROOF_KEY[member] + s})
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": jwk}
    assert _has_escape(json.dumps(header))
    hostile = _unsigned_proof(header)
    for given in (_request(hostile), json.dumps(_request(hostile))):
        with pytest.raises(ClaimsInvalid, match="cannot be thumbprinted") as exc:
            _verify_proofs(given)
        assert type(exc.value) is ClaimsInvalid
    # an attested key, with a key_attestation that lists it. The control lists a benign
    # different key: it is thumbprinted, and refused as "not among the attested keys".
    with pytest.raises(ClaimsInvalid, match="not among") as aexc:
        _verify_proofs(_request(_unsigned_proof(
            {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": PROOF_KEY,
             "key_attestation": _attestation([benign])})))
    assert type(aexc.value) is ClaimsInvalid
    attestation = _attestation([dict(PROOF_KEY, **{member: PROOF_KEY[member] + s})])
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": PROOF_KEY,
              "key_attestation": attestation}
    hostile = _unsigned_proof(header)
    for given in (_request(hostile), json.dumps(_request(hostile))):
        with pytest.raises(ClaimsInvalid, match="cannot be thumbprinted") as exc:
            _verify_proofs(given)
        assert type(exc.value) is ClaimsInvalid


# --------------------------------------------------------------------------- #
# no accept-set change: a valid non-BMP character (a surrogate PAIR) still works
# --------------------------------------------------------------------------- #

PAIR = "\U0001F600"                       # U+1F600, two UTF-16 code units, one code point


def _pair_wire(obj):
    """Through JSON as ``\\ud83d\\ude00`` and back, the way a hostile-looking but valid
    emoji arrives."""
    text = json.dumps(obj)
    assert "\\ud83d\\ude00" in text
    return _json.loads(text)


@pytest.mark.parametrize("suite", list(RDF_SUITES))
def test_pair_signs_and_verifies_on_the_rdf_suites(suite):
    cls, key, did = RDF_SUITES[suite]
    doc = _credential(did)
    doc["credentialSubject"]["name"] = "Alice " + PAIR
    signed = cls().add_proof(doc, signing_key=key, verification_method=key.kid)
    assert verify_credential(_pair_wire(signed)).issuer == did
    assert verify_credential(signed).issuer == did


@pytest.mark.parametrize("make", [
    lambda: (EddsaJcsProofSuite, ED, ED_DID), lambda: (EcdsaJcsProofSuite, P256, P256_DID)],
    ids=["eddsa-jcs-2022", "ecdsa-jcs-2019"])
def test_pair_signs_and_verifies_on_the_jcs_suites(make):
    cls, key, did = make()
    doc = _credential(did)
    doc["credentialSubject"]["name"] = "Alice " + PAIR
    signed = cls().add_proof(doc, signing_key=key, verification_method=key.kid)
    assert verify_credential(_pair_wire(signed)).issuer == did


def test_pair_signs_derives_and_verifies_on_ecdsa_sd():
    doc = _sd_credential()
    doc["credentialSubject"]["name"] = "Alice " + PAIR
    base = SD.add_base_proof(doc, signing_key=P256, verification_method=P256.kid,
                             mandatory_pointers=["/issuer", "/credentialSubject/description"])
    derived = SD.derive_proof(base, selective_pointers=["/credentialSubject/name"])
    assert derived["credentialSubject"]["name"] == "Alice " + PAIR
    assert verify_credential(_pair_wire(derived)).issuer == P256_DID
    # ... also as a mandatory statement
    base = SD.add_base_proof(doc, signing_key=P256, verification_method=P256.kid,
                             mandatory_pointers=["/issuer", "/credentialSubject/name"])
    assert verify_credential(_pair_wire(SD.derive_proof(base, selective_pointers=[]))
                             ).issuer == P256_DID


def test_pair_signs_and_verifies_on_vc_jwt_and_sd_jwt_vc():
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
          "credentialSubject": {"id": "did:example:alice", "name": "Alice " + PAIR}}
    token = VcJwtProofSuite().sign(vc, signing_key=P256)
    assert verify_credential(token).credential["credentialSubject"]["name"] == "Alice " + PAIR
    sd = SdJwtVcProofSuite()
    issued = sd.issue({"iss": P256_DID, "vct": "urn:example:vct", "name": "Alice " + PAIR,
                       "other": "x"}, signing_key=P256, disclosable=["name"])
    assert verify_credential(issued).issuer == P256_DID


def test_pair_in_a_signed_proof_header_jwk_member_keeps_its_thumbprint():
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "AAAA" + PAIR}
    assert jwk_thumbprint(jwk)


# --------------------------------------------------------------------------- #
# the JOSE lanes keep accepting a SIGNED surrogate (the issuer signed those bytes)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("s", SURROGATES)
def test_signed_surrogate_on_the_jose_lanes_is_unchanged(s):
    # json.dumps escapes it, the signature covers the escaped bytes, and it verifies. Not a
    # wrong-accept, and this fix does not touch the accept set (the loader still allows it).
    vc = {"@context": [V2], "type": ["VerifiableCredential"], "issuer": P256_DID,
          "credentialSubject": {"id": "did:example:alice", "name": "Alice" + s}}
    token = VcJwtProofSuite().sign(vc, signing_key=P256)
    assert verify_credential(token).credential["credentialSubject"]["name"] == "Alice" + s
    issued = SdJwtVcProofSuite().issue(
        {"iss": P256_DID, "vct": "urn:example:vct", "name": "Alice" + s, "other": "x"},
        signing_key=P256, disclosable=["name"])
    assert verify_credential(issued).issuer == P256_DID
