"""
tests/test_vc_api_shim.py — the VC-API conformance shim (issue #69) stays working.

The shim under ``tests/tools/`` is what the official W3C suites drive; this pins that it
issues and verifies each Data Integrity cryptosuite through the VC-API contract (pure
functions and over real HTTP), so it does not rot between conformance runs. ``tests/`` is
not a package, so the shim is loaded by path (never cross-imported).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import threading
import urllib.error
import urllib.request

import pytest

pytest.importorskip("pyld")            # the RDF cryptosuites (eddsa/ecdsa-rdfc) need pyld

_SHIM_PATH = pathlib.Path(__file__).parent / "tools" / "vc_api_shim.py"


def _load_shim():
    spec = importlib.util.spec_from_file_location("vc_api_shim", _SHIM_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


shim = _load_shim()

_CREDENTIAL = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:0c71c1e0-0f3a-4b6e-9a1a-000000000069",
    "type": ["VerifiableCredential"],
    "issuer": "did:example:issuer",
    "credentialSubject": {"id": "did:example:subject", "alumniOf": "Example University"},
}

_CRYPTOSUITES = ["eddsa-rdfc-2022", "eddsa-jcs-2022", "ecdsa-rdfc-2019", "ecdsa-jcs-2019"]


@pytest.mark.parametrize("cryptosuite", _CRYPTOSUITES)
def test_issue_then_verify_roundtrip(cryptosuite):
    status, body = shim.issue(
        {"credential": _CREDENTIAL, "options": {"cryptosuite": cryptosuite}})
    assert status == 201, body
    vc = body["verifiableCredential"]
    assert vc["proof"]["cryptosuite"] == cryptosuite
    assert vc["proof"]["verificationMethod"].startswith("did:key:z")   # independently resolvable

    status, result = shim.verify({"verifiableCredential": vc})
    assert status == 200 and result["errors"] == []


def test_ecdsa_p384_track():
    status, body = shim.issue(
        {"credential": _CREDENTIAL, "options": {"cryptosuite": "ecdsa-rdfc-2019"}},
        ecdsa_curve="P-384")
    assert status == 201
    vc = body["verifiableCredential"]
    assert shim.verify({"verifiableCredential": vc})[0] == 200


def test_tampered_credential_fails_verify():
    _, body = shim.issue(
        {"credential": _CREDENTIAL, "options": {"cryptosuite": "eddsa-jcs-2022"}})
    vc = body["verifiableCredential"]
    vc["credentialSubject"]["alumniOf"] = "Forged University"        # break the signed content
    status, result = shim.verify({"verifiableCredential": vc})
    assert status == 400 and result["errors"]


def test_unsupported_cryptosuite_is_400_not_500():
    status, body = shim.issue(
        {"credential": _CREDENTIAL, "options": {"cryptosuite": "made-up-2099"}})
    assert status == 400 and body["errors"]


def test_missing_credential_is_400():
    assert shim.issue({"options": {"cryptosuite": "eddsa-jcs-2022"}})[0] == 400
    assert shim.verify({})[0] == 400


def test_presentation_verify_roundtrip():
    from openvc.keys import Ed25519SigningKey
    from openvc.proof.di_jcs import EddsaJcsProofSuite

    vc = shim.issue(
        {"credential": _CREDENTIAL, "options": {"cryptosuite": "eddsa-jcs-2022"}}
    )[1]["verifiableCredential"]
    holder = Ed25519SigningKey.generate("holder")
    vm = shim._did_key("Ed25519", holder.public_key_raw())
    vp = {"@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": ["VerifiablePresentation"], "verifiableCredential": [vc]}
    secured_vp = EddsaJcsProofSuite().add_proof(
        vp, signing_key=holder, verification_method=vm, proof_purpose="authentication",
        challenge="n-0S6_WzA2Mj", domain="https://verifier.example")

    status, result = shim.verify_presentation(
        {"verifiablePresentation": secured_vp,
         "options": {"challenge": "n-0S6_WzA2Mj", "domain": "https://verifier.example"}})
    assert status == 200 and result["errors"] == []


# --------------------------------------------------------------------------- #
# over real HTTP (the transport the W3C harness actually uses)
# --------------------------------------------------------------------------- #

def _post(port: int, path: str, body: dict):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_http_issue_and_verify():
    server = shim.make_server()
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _post(port, "/credentials/issue",
                             {"credential": _CREDENTIAL,
                              "options": {"cryptosuite": "eddsa-jcs-2022"}})
        assert status == 201
        status, result = _post(
            port, "/credentials/verify",
            {"verifiableCredential": body["verifiableCredential"]})
        assert status == 200 and result["errors"] == []
        # a tampered VC over HTTP -> 400
        forged = body["verifiableCredential"]
        forged["credentialSubject"]["alumniOf"] = "Forged"
        status, _ = _post(port, "/credentials/verify", {"verifiableCredential": forged})
        assert status == 400
    finally:
        server.shutdown()
        thread.join(timeout=5)
