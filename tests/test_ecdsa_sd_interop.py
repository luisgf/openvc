"""
tests/test_ecdsa_sd_interop.py — ecdsa-sd-2023 interop against the official W3C
`vc-di-ecdsa` test vectors (needs pyld).

Two checks per example (`prc`, `employ`):
  * verifier side — `verify` accepts a reference-produced derived proof;
  * issuer side — our HMAC-relabeled canonical N-Quads and the proof/mandatory
    hashes match the recorded intermediates byte for byte.

ECDSA is randomised, so (unlike eddsa-rdfc-2022) correctness cannot be shown by
reproducing a fixed proof value — these deterministic checks are the interop seal.
See `tests/fixtures/ecdsa_sd/README.md` for provenance.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pyld")

from openvc.proof import ecdsa_sd as m  # noqa: E402
from openvc.proof.contexts import document_loader  # noqa: E402
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite, SignatureInvalid  # noqa: E402

FX = Path(__file__).parent / "fixtures" / "ecdsa_sd"
CITIZENSHIP = "https://w3id.org/citizenship/v4rc1"
EXAMPLES = ["prc", "employ"]


@pytest.fixture(scope="module")
def extra_contexts() -> dict:
    return {CITIZENSHIP: json.loads((FX / "citizenship-v4rc1.json").read_text())}


def _load(example: str, name: str) -> dict:
    return json.loads((FX / example / name).read_text())


@pytest.mark.parametrize("example", EXAMPLES)
def test_verifies_w3c_reference_derived_proof(example, extra_contexts):
    reveal = _load(example, "derivedRevealDocument.json")
    # No injected key: the P-256 verificationMethod resolves via did:key.
    result = EcdsaSdProofSuite().verify(reveal, extra_contexts=extra_contexts)
    assert result.proof["cryptosuite"] == "ecdsa-sd-2023"
    assert result.issuer and result.issuer.startswith("did:key:")


@pytest.mark.parametrize("example", EXAMPLES)
def test_issuer_pipeline_matches_w3c_intermediates(example, extra_contexts):
    signed = _load(example, "addSignedSDBase.json")
    proof = signed["proof"]
    doc = {k: v for k, v in signed.items() if k != "proof"}
    base = m.parse_base_proof(proof["proofValue"])
    loader = document_loader(extra_contexts)

    transform = m._transform(doc, base["hmac_key"], loader)
    ref_hmac = [ln.rstrip("\n") for ln in _load(example, "addBaseDocHMACCanon.json")
                if ln.strip()]
    assert sorted(transform.relabeled) == sorted(ref_hmac)   # byte-exact HMAC canon

    hashes = _load(example, "addHashData.json")
    assert m._proof_config_hash(proof, doc["@context"], loader).hex() == hashes["proofHash"]

    mandatory_set = m._selection_lines(
        m.select_json_ld(base["mandatory_pointers"], transform.skolemized_compact) or {},
        transform.skolem_to_hmac, loader)
    mandatory_lines = [ln for ln in transform.relabeled if ln in mandatory_set]
    assert m._sha256_lines(mandatory_lines).hex() == hashes["mandatoryHash"]


@pytest.mark.parametrize("example", EXAMPLES)
def test_tampering_a_reference_proof_is_rejected(example, extra_contexts):
    reveal = _load(example, "derivedRevealDocument.json")
    reveal["proof"]["created"] = "1999-01-01T00:00:00Z"      # part of the signed proof config
    with pytest.raises(SignatureInvalid):
        EcdsaSdProofSuite().verify(reveal, extra_contexts=extra_contexts)
