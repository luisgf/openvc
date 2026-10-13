"""
tests/test_unhashable_proof_purpose.py — a Data Integrity ``proofPurpose`` that is a
JSON array or object fails closed and typed (#208).

Every Data Integrity suite resolves the signing key before checking the signature, and
looks the proof's own ``proofPurpose`` up in the DID document's verification
relationships (``DidDocument.key_for_purpose``, a ``dict.get``). A list or dict is
unhashable, so the lookup raised a bare ``TypeError`` — outside the ``OpenvcError``
family, so it aborted ``verify_many`` / ``verify_many_async``. No key was needed: the
lookup runs before any crypto. Found by a sweep of ``src/`` after the adversarial
review of #197; the JOSE header lanes of the same bug are fixed in #211.

Also pinned here: the WRPRC ``typ`` error message names an array or object by its type
instead of quoting it, like the other allow-list messages (#211). Since #213 refuses
JSON nested past 100 levels where it enters, that is defence in depth.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import importlib.util
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from openvc import verify_credential, verify_many
from openvc.aio import verify_many_async
from openvc.did.did_key import DidKeyResolver
from openvc.errors import OpenvcError
from openvc.multibase import encode_multibase
from openvc.proof._verify_common import resolve_verification_key
from openvc.proof.errors import ProofMalformed
from openvc.rp_registration import RpRegistrationError, verify_rp_registration_certificate

_DEEP = 100_000                         # parses on 3.14; repr() overflows the stack


def _deep_list() -> list:
    return json.loads("[" * _DEEP + "]" * _DEEP)


def _deep_parses() -> bool:
    """Only CPython 3.14+'s iterative JSON scanner parses the deep array; elsewhere
    json.loads raises (typed at every openvc parse site), so the shape is unreachable."""
    try:
        _deep_list()
    except RecursionError:
        return False
    return True


_DEEP_PARSES = _deep_parses()
needs_deep_json = pytest.mark.skipif(
    not _DEEP_PARSES, reason="this interpreter's JSON scanner rejects the deep array")
# the RDF suites canonicalize first and, without pyld, fail typed on that instead
_needs_pyld = pytest.mark.skipif(importlib.util.find_spec("pyld") is None,
                                 reason="needs pyld (the [data-integrity] extra)")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ed25519_did_key() -> tuple[str, str]:
    pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    mb = encode_multibase(b"\xed\x01" + pub)
    return f"did:key:{mb}", f"did:key:{mb}#{mb}"


def _ecdsa_sd_proof_value() -> str:
    """A well-formed derived ecdsa-sd-2023 proofValue (zero signatures): enough to
    reach the key lookup, which runs before the base signature is checked."""
    from openvc import cbor
    from openvc.proof.ecdsa_sd import DERIVED_PROOF_HEADER

    return "u" + _b64(DERIVED_PROOF_HEADER + cbor.encode([bytes(64), bytes(35), [], {}, []]))


DI_SUITES = [pytest.param("eddsa-rdfc-2022", marks=_needs_pyld), "eddsa-jcs-2022",
             "ecdsa-rdfc-2019", "ecdsa-jcs-2019",
             pytest.param("ecdsa-sd-2023", marks=_needs_pyld)]
SHAPES = [["assertionMethod"], {"a": 1}]
SHAPE_IDS = ["list", "object"]


def _di_credential(cryptosuite: str, purpose) -> dict:
    did, vm = _ed25519_did_key()
    proof_value = (_ecdsa_sd_proof_value() if cryptosuite == "ecdsa-sd-2023"
                   else encode_multibase(bytes(64)))
    return {"@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"], "issuer": did,
            "credentialSubject": {"id": "did:example:alice"},
            "proof": {"type": "DataIntegrityProof", "cryptosuite": cryptosuite,
                      "verificationMethod": vm, "proofPurpose": purpose,
                      "proofValue": proof_value}}


@pytest.mark.parametrize("cryptosuite", DI_SUITES)
@pytest.mark.parametrize("value", SHAPES, ids=SHAPE_IDS)
def test_proof_purpose_shape_is_typed(cryptosuite, value):
    with pytest.raises(ProofMalformed, match="proofPurpose must be a string, not"):
        verify_credential(_di_credential(cryptosuite, value))


@needs_deep_json
@pytest.mark.parametrize("cryptosuite", DI_SUITES)
def test_deep_proof_purpose_is_typed(cryptosuite):
    # refused where it enters (#213), before any suite reads the purpose
    with pytest.raises(OpenvcError):
        verify_credential(_di_credential(cryptosuite, _deep_list()))


@pytest.mark.parametrize("cryptosuite", DI_SUITES)
@pytest.mark.parametrize("value", SHAPES, ids=SHAPE_IDS)
def test_proof_purpose_shape_does_not_abort_a_batch(cryptosuite, value):
    hostile = _di_credential(cryptosuite, value)
    batch = [hostile, "not.a.jwt", hostile]
    for results in (verify_many(batch), asyncio.run(verify_many_async(batch))):
        assert [r.index for r in results] == [0, 1, 2]
        assert all((not r.ok) and isinstance(r.error, OpenvcError) for r in results)
        assert isinstance(results[0].error, ProofMalformed)
        assert isinstance(results[2].error, ProofMalformed)


@pytest.mark.parametrize("value", SHAPES, ids=SHAPE_IDS)
def test_key_for_purpose_fails_closed_on_a_non_string(value):
    did, vm = _ed25519_did_key()
    doc = DidKeyResolver().resolve(did)
    assert doc.key_for_purpose(vm, "assertionMethod") is not None
    assert doc.key_for_purpose(vm, value) is None


@pytest.mark.parametrize("value", SHAPES + [0, False], ids=SHAPE_IDS + ["zero", "false"])
def test_junk_proof_purpose_never_reaches_the_resolver(value):
    """The guard runs before DID resolution: a junk purpose costs no did:web fetch."""
    calls = []

    class _Recording:
        def supports(self, did):
            return True

        def resolve(self, did):
            calls.append(did)
            raise AssertionError("resolver reached")

    with pytest.raises(ProofMalformed, match="proofPurpose must be a string"):
        resolve_verification_key("did:web:verifier.example#k", proof_purpose=value,
                                 resolver=_Recording())
    assert calls == []


def _self_signed_cert() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "registrar")])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))


@pytest.mark.parametrize("value", SHAPES, ids=SHAPE_IDS)
def test_wrprc_typ_message_names_the_shape(value):
    header = _b64(json.dumps({"alg": "ES256", "typ": value}).encode())
    token = f"{header}.{_b64(b'{}')}.{_b64(bytes(64))}"
    name = type(value).__name__
    with pytest.raises(RpRegistrationError, match=f"WRPRC typ must be .*, got {name}$"):
        verify_rp_registration_certificate(token, trust_anchors=[_self_signed_cert()])


def test_wrprc_deep_typ_is_typed():
    # refused where it enters (#213), before the typ check ever sees it
    deep = "[" * _DEEP + "]" * _DEEP
    header = _b64(('{"alg":"ES256","typ":' + deep + "}").encode())
    token = f"{header}.{_b64(b'{}')}.{_b64(bytes(64))}"
    with pytest.raises(RpRegistrationError):
        verify_rp_registration_certificate(token, trust_anchors=[_self_signed_cert()])
