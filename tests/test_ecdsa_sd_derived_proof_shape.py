"""
tests/test_ecdsa_sd_derived_proof_shape.py — a hostile ``ecdsa-sd-2023`` derived proof
value is a typed :class:`ProofError`, never a bare ``TypeError`` / ``AttributeError``.

The derived proof value is a CBOR array the holder writes: ``[base_signature,
public_key, signatures, compressed label map, mandatory_indexes]``. ``decode_derived_proof``
checked only that it was a five-element array, so a part of another CBOR type reached
the verifier as is:

* a text-string or integer ``public_key`` broke ``proof_hash + public_key + ...`` with
  ``TypeError`` — before the issuer's key is resolved, so no key or signature at all;
* an array or text-string label map broke ``decompress_label_map`` (``.items()``) with
  ``AttributeError``, which the caller's ``except`` tuple did not list;
* an integer ``signatures`` broke ``len()`` with ``TypeError`` once the (genuine) base
  signature verified.

Each escaped ``verify_credential`` and ``verify_credential_async``, and aborted a whole
``verify_many`` / ``verify_many_async`` batch — the #279 / #208 class (threat model I14,
I15). Each part is now typed in ``decode_derived_proof`` (``ProofValueMalformed``), and
``AttributeError`` joined the backstop around it. A label map that gives two blank
nodes one label is refused there too: it is a wrong-accept, not a crash (section 19 of
``test_di_context_validation.py``). Self-contained (tests/ is not a package);
``asyncio.run`` drives the coroutines.
"""
from __future__ import annotations

import asyncio
import base64
import copy

import pytest

from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.proof import ecdsa_sd
from openvc.proof.ecdsa_sd import (
    DERIVED_PROOF_HEADER,
    ProofValueMalformed,
    compress_label_map,
    decode_derived_proof,
    encode_cbor,
)
from openvc.proof.errors import ProofError

V2 = "https://www.w3.org/ns/credentials/v2"
DID = "did:example:issuer"
VM = f"{DID}#k"


def _encode(parts):
    raw = DERIVED_PROOF_HEADER + encode_cbor(parts)
    return "u" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _parts(proof_value):
    """The five CBOR parts of a genuine derived proof value, label map compressed."""
    parsed = decode_derived_proof(proof_value)
    return [parsed["base_signature"], parsed["public_key"], parsed["signatures"],
            compress_label_map(parsed["label_map"]), parsed["mandatory_indexes"]]


_GENUINE = [b"\x01" * 64, b"\x02" * 35, [b"\x03" * 64], {0: b"\x04" * 32}, [0, 2]]

# (case, position in the CBOR array, the hostile part)
_HOSTILE = [
    ("base-signature-text", 0, "sig"),
    ("base-signature-int", 0, 7),
    ("base-signature-array", 0, [b"\x01"]),
    ("public-key-text", 1, "text"),
    ("public-key-int", 1, 7),
    ("public-key-map", 1, {0: b"\x02"}),
    ("signatures-int", 2, 5),
    ("signatures-bytes", 2, b"\x03" * 64),
    ("signatures-text-item", 2, ["sig"]),
    ("signatures-int-item", 2, [5]),
    ("label-map-array", 3, []),
    ("label-map-text", 3, "text"),
    ("label-map-text-key", 3, {"c14n0": b"\x04" * 32}),
    ("label-map-text-value", 3, {0: "u" + "A" * 43}),
    ("label-map-int-value", 3, {0: 4}),
    # two blank nodes, one HMAC label: one node to the signature, two to the JSON
    # (test_di_context_validation.py section 19)
    ("label-map-not-injective", 3, {0: b"\x04" * 32, 1: b"\x04" * 32}),
    ("mandatory-indexes-int", 4, 3),
    ("mandatory-indexes-text-item", 4, ["0"]),
    ("mandatory-indexes-map", 4, {0: 1}),
]


@pytest.mark.parametrize("position, hostile", [c[1:] for c in _HOSTILE],
                         ids=[c[0] for c in _HOSTILE])
def test_decode_derived_proof_types_every_part(position, hostile):
    parts = list(_GENUINE)
    parts[position] = hostile
    with pytest.raises(ProofValueMalformed, match="derived proof"):
        decode_derived_proof(_encode(parts))


def test_decode_derived_proof_still_accepts_the_genuine_shape():
    parsed = decode_derived_proof(_encode(_GENUINE))
    assert parsed["signatures"] == [b"\x03" * 64]
    assert parsed["mandatory_indexes"] == [0, 2]
    assert list(parsed["label_map"]) == ["c14n0"]
    empty = decode_derived_proof(_encode([b"\x01" * 64, b"\x02" * 35, [], {}, []]))
    assert empty["signatures"] == [] and empty["label_map"] == {}
    two = list(_GENUINE)
    two[3] = {0: b"\x04" * 32, 1: b"\x05" * 32}
    assert sorted(decode_derived_proof(_encode(two))["label_map"]) == ["c14n0", "c14n1"]


# --------------------------------------------------------------------------- #
# Through the suite and the pipelines, on a genuine derived credential
# --------------------------------------------------------------------------- #

def _registry(public_jwk):
    from openvc.did.base import DidResolutionError, parse_did_document

    doc = parse_did_document({
        "id": DID,
        "verificationMethod": [
            {"id": VM, "type": "JsonWebKey2020", "controller": DID, "publicKeyJwk": public_jwk}],
        "assertionMethod": [VM],
    })

    class _Reg:
        def supports(self, did):
            return did == DID

        def resolve(self, did):
            if did != DID:
                raise DidResolutionError(f"unknown DID {did!r}")
            return doc

    return _Reg()


@pytest.fixture(scope="module")
def derived():
    """A genuine derived credential and its issuer key."""
    pytest.importorskip("pyld")
    key = P256SigningKey.generate(kid=VM)
    doc = {"@context": [V2], "id": "urn:uuid:7d1e5c38-0000-4000-8000-0000000000aa",
           "type": ["VerifiableCredential"], "issuer": DID,
           "validFrom": "2020-01-01T00:00:00Z",
           "credentialSubject": {"id": "did:example:alice", "name": "Alice"}}
    suite = ecdsa_sd.EcdsaSdProofSuite()
    base = suite.add_base_proof(doc, signing_key=key, verification_method=VM,
                                mandatory_pointers=["/issuer", "/validFrom"])
    return suite.derive_proof(base, selective_pointers=["/credentialSubject/name"]), key


def _hostile(derived, position, part):
    out = copy.deepcopy(derived)
    parts = _parts(out["proof"]["proofValue"])
    parts[position] = part
    out["proof"]["proofValue"] = _encode(parts)
    return out


# The finding's five (key-less for the public key and the label map; the integer
# `signatures` is read only after the genuine base signature verifies) plus the other
# parts the verifier reads.
_PIPELINE = [
    ("public-key-text", 1, "text"),
    ("public-key-int", 1, 7),
    ("label-map-array", 3, []),
    ("label-map-text", 3, "text"),
    ("signatures-int", 2, 5),
    ("signatures-text-item", 2, ["sig"]),
    ("base-signature-text", 0, "sig"),
    ("mandatory-indexes-int", 4, 3),
]


@pytest.mark.parametrize("position, part", [c[1:] for c in _PIPELINE],
                         ids=[c[0] for c in _PIPELINE])
def test_hostile_derived_proof_value_is_a_typed_proof_error(derived, position, part):
    from openvc import verify_credential, verify_credential_async, verify_many_async
    from openvc.did.base import as_async_resolver
    from openvc.verify import verify_many

    genuine, key = derived
    hostile = _hostile(genuine, position, part)
    suite = ecdsa_sd.EcdsaSdProofSuite()
    with pytest.raises(ProofValueMalformed):
        suite.verify(copy.deepcopy(hostile), public_key_jwk=key.public_jwk())
    # no usable key needed: an unrelated issuer key changes nothing
    other = P256SigningKey.generate(kid=VM).public_jwk()
    with pytest.raises(ProofValueMalformed):
        suite.verify(copy.deepcopy(hostile), resolver=_registry(other))

    registry = _registry(key.public_jwk())
    with pytest.raises(ProofError):
        verify_credential(copy.deepcopy(hostile), resolver=registry)
    with pytest.raises(ProofError):
        asyncio.run(verify_credential_async(copy.deepcopy(hostile),
                                            resolver=as_async_resolver(registry)))

    batch = verify_many([genuine, hostile, genuine], resolver=registry)
    assert [r.error is None for r in batch] == [True, False, True]
    assert isinstance(batch[1].error, ProofError)
    batch = asyncio.run(verify_many_async([genuine, hostile, genuine],
                                          resolver=as_async_resolver(registry)))
    assert [r.error is None for r in batch] == [True, False, True]
    assert isinstance(batch[1].error, ProofError)


def test_genuine_derived_credential_still_verifies(derived):
    genuine, key = derived
    verified = ecdsa_sd.EcdsaSdProofSuite().verify(copy.deepcopy(genuine),
                                                   public_key_jwk=key.public_jwk())
    assert verified.issuer == DID


@pytest.mark.parametrize("raised", [AttributeError, TypeError, KeyError, IndexError,
                                    ValueError])
def test_an_unforeseen_decode_failure_is_still_typed(derived, monkeypatch, raised):
    # The backstop around decode_derived_proof: a shape it does not type itself still
    # leaves verify() as ProofValueMalformed, never as the bare exception.
    genuine, key = derived

    def broken(_):
        raise raised("unforeseen")

    monkeypatch.setattr(ecdsa_sd, "decode_derived_proof", broken)
    with pytest.raises(ProofValueMalformed) as info:
        ecdsa_sd.EcdsaSdProofSuite().verify(copy.deepcopy(genuine),
                                            public_key_jwk=key.public_jwk())
    assert isinstance(info.value, OpenvcError)
