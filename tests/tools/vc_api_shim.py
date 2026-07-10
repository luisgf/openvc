"""
tests/tools/vc_api_shim.py — a **test-only** VC-API shim over openvc.

The official W3C conformance suites (``vc-data-model-2.0``, ``vc-di-eddsa``,
``vc-di-ecdsa``, ``bitstring-status-list``) are driven through the **VC-API** HTTP
endpoints (``w3c/vc-test-suite-implementations``): the harness POSTs a credential to an
*issuer* endpoint and a verifiable credential/presentation to a *verifier* endpoint.
This shim exposes exactly those endpoints, backed by openvc's Data Integrity suites, so
openvc can be registered in the **public implementation reports** — third-party
conformance evidence a single-maintainer library cannot get any other way (the golden
fixtures prove drift *to us*; the reports prove conformance *to everyone else*).

It is **not** a shipped API surface: it lives under ``tests/``, adds **no runtime
dependency** (stdlib ``http.server`` only), keys are ephemeral per process, and it does
no auth / TLS / persistence. Run it manually before a release (or in a scheduled CI job)
against the suites — see ``tests/tools/README.md``. The Data Integrity RDF cryptosuites
need the ``[data-integrity]`` extra (``pyld``).

Endpoints (VC-API):

* ``POST /credentials/issue`` — issue a VC (``{credential, options:{cryptosuite}}``).
* ``POST /credentials/verify`` — verify a VC (``{verifiableCredential, options}``).
* ``POST /presentations/verify`` — verify a VP (``{verifiablePresentation, options}``).

Supported cryptosuites: ``eddsa-rdfc-2022``, ``eddsa-jcs-2022``, ``ecdsa-rdfc-2019``,
``ecdsa-jcs-2019``. The ECDSA curve defaults to P-256; set ``OPENVC_SHIM_ECDSA_CURVE=P-384``
(or pass ``ecdsa_curve="P-384"`` to :func:`issue`) for the P-384 track.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from openvc import VerificationPolicy, verify_credential
from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey
from openvc.multibase import encode_multibase

# did:key multicodec varint prefixes (unsigned-varint of the multicodec code).
_MULTICODEC = {"Ed25519": b"\xed\x01", "P-256": b"\x80\x24", "P-384": b"\x81\x24"}


def _did_key(kind: str, raw_public: bytes) -> str:
    """A did:key verificationMethod for *raw_public* (so any verifier resolves it)."""
    multibase = encode_multibase(_MULTICODEC[kind] + raw_public)
    return f"did:key:{multibase}#{multibase}"


def _issuer(cryptosuite: str, ecdsa_curve: str) -> tuple[Any, Any, str]:
    """(proof suite, signing key, did:key verificationMethod) for *cryptosuite*."""
    if cryptosuite in ("eddsa-rdfc-2022", "eddsa-jcs-2022"):
        key = Ed25519SigningKey.generate("shim")
        vm = _did_key("Ed25519", key.public_key_raw())
        if cryptosuite == "eddsa-rdfc-2022":
            from openvc.proof.data_integrity import DataIntegrityProofSuite
            return DataIntegrityProofSuite(), key, vm
        from openvc.proof.di_jcs import EddsaJcsProofSuite
        return EddsaJcsProofSuite(), key, vm
    if cryptosuite in ("ecdsa-rdfc-2019", "ecdsa-jcs-2019"):
        if ecdsa_curve == "P-384":
            key = P384SigningKey.generate("shim")
            vm = _did_key("P-384", key.public_key_raw())
        else:
            key = P256SigningKey.generate("shim")
            vm = _did_key("P-256", key.public_key_raw())
        if cryptosuite == "ecdsa-rdfc-2019":
            from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
            return EcdsaRdfcProofSuite(), key, vm
        from openvc.proof.di_jcs import EcdsaJcsProofSuite
        return EcdsaJcsProofSuite(), key, vm
    raise ValueError(f"unsupported cryptosuite {cryptosuite!r}")


def _verify_suite(cryptosuite: str) -> Any:
    if cryptosuite == "eddsa-rdfc-2022":
        from openvc.proof.data_integrity import DataIntegrityProofSuite
        return DataIntegrityProofSuite()
    if cryptosuite == "eddsa-jcs-2022":
        from openvc.proof.di_jcs import EddsaJcsProofSuite
        return EddsaJcsProofSuite()
    if cryptosuite == "ecdsa-rdfc-2019":
        from openvc.proof.di_ecdsa_rdfc import EcdsaRdfcProofSuite
        return EcdsaRdfcProofSuite()
    if cryptosuite == "ecdsa-jcs-2019":
        from openvc.proof.di_jcs import EcdsaJcsProofSuite
        return EcdsaJcsProofSuite()
    raise ValueError(f"unsupported cryptosuite {cryptosuite!r}")


def _default_ecdsa_curve() -> str:
    return "P-384" if os.environ.get("OPENVC_SHIM_ECDSA_CURVE") == "P-384" else "P-256"


# --------------------------------------------------------------------------- #
# VC-API operations (pure functions -> (status_code, body dict); HTTP-agnostic)
# --------------------------------------------------------------------------- #

def issue(body: dict[str, Any], *, ecdsa_curve: str | None = None) -> tuple[int, dict[str, Any]]:
    """VC-API ``/credentials/issue``: secure ``body['credential']`` with the Data
    Integrity ``body['options']['cryptosuite']`` proof and return the verifiable credential."""
    credential = body.get("credential")
    options = body.get("options") or {}
    cryptosuite = options.get("cryptosuite", "eddsa-rdfc-2022")
    if not isinstance(credential, dict):
        return 400, {"errors": ["request body needs a 'credential' object"]}
    curve = ecdsa_curve or _default_ecdsa_curve()
    try:
        suite, key, vm = _issuer(cryptosuite, curve)
        # The issuer endpoint issues as ITS OWN identity: openvc (like most DI verifiers)
        # binds the proof verificationMethod to the credential issuer, so set the issuer to
        # the shim's did:key (the VM controller) — the standard VC-API issuer behaviour.
        credential = dict(credential)
        credential["issuer"] = vm.split("#", 1)[0]
        secured = suite.add_proof(credential, signing_key=key, verification_method=vm)
    except Exception as exc:                                # a bad request -> 400, not a 500
        return 400, {"errors": [f"{type(exc).__name__}: {exc}"]}
    return 201, {"verifiableCredential": secured}


def verify(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """VC-API ``/credentials/verify``: verify ``body['verifiableCredential']`` (200 valid,
    400 invalid) with a ``{checks, warnings, errors}`` result."""
    vc = body.get("verifiableCredential")
    if not isinstance(vc, (dict, str)):
        return 400, {"checks": [], "warnings": [],
                     "errors": ["request needs a 'verifiableCredential'"]}
    try:
        verify_credential(vc, policy=VerificationPolicy(require_status=False))
    except Exception as exc:
        return 400, {"checks": [], "warnings": [], "errors": [f"{type(exc).__name__}: {exc}"]}
    return 200, {"checks": ["proof"], "warnings": [], "errors": []}


def verify_presentation(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """VC-API ``/presentations/verify``: verify a Data Integrity verifiable presentation's
    ``authentication`` proof (bound to ``options.challenge`` / ``options.domain``) and
    cascade-verify every embedded credential."""
    vp = body.get("verifiablePresentation")
    options = body.get("options") or {}
    if not isinstance(vp, dict):
        return 400, {"checks": [], "warnings": [],
                     "errors": ["request needs a 'verifiablePresentation'"]}
    proof = vp.get("proof")
    proof = proof[0] if isinstance(proof, list) and proof else proof
    cryptosuite = proof.get("cryptosuite") if isinstance(proof, dict) else None
    try:
        suite = _verify_suite(cryptosuite) if isinstance(cryptosuite, str) else None
        if suite is None:
            raise ValueError(f"unsupported presentation cryptosuite {cryptosuite!r}")
        suite.verify(dict(vp), expected_proof_purpose="authentication",
                     expected_challenge=options.get("challenge"),
                     expected_domain=options.get("domain"))
        embedded = vp.get("verifiableCredential")
        items = embedded if isinstance(embedded, list) else [embedded] if embedded else []
        for credential in items:
            verify_credential(credential, policy=VerificationPolicy(require_status=False))
    except Exception as exc:
        return 400, {"checks": [], "warnings": [], "errors": [f"{type(exc).__name__}: {exc}"]}
    return 200, {"checks": ["proof"], "warnings": [], "errors": []}


_ROUTES = {
    "/credentials/issue": issue,
    "/credentials/verify": verify,
    "/presentations/verify": verify_presentation,
}


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #

class VcApiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:                # keep test output quiet
        pass

    def do_POST(self) -> None:                                # noqa: N802 (stdlib name)
        handler = _ROUTES.get(self.path.split("?", 1)[0])
        if handler is None:
            return self._send(404, {"errors": [f"no such endpoint {self.path!r}"]})
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError) as exc:
            return self._send(400, {"errors": [f"invalid JSON body: {exc}"]})
        if not isinstance(body, dict):
            return self._send(400, {"errors": ["request body must be a JSON object"]})
        status, payload = handler(body)
        self._send(status, payload)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """A stopped :class:`ThreadingHTTPServer` for the shim (``port=0`` picks a free port)."""
    return ThreadingHTTPServer((host, port), VcApiHandler)


def main() -> None:                                           # pragma: no cover - manual runs
    import argparse

    parser = argparse.ArgumentParser(description="openvc VC-API conformance shim (test-only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = make_server(args.host, args.port)
    print(f"openvc VC-API shim on http://{args.host}:{server.server_address[1]}  "
          f"(ecdsa curve: {_default_ecdsa_curve()})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":                                    # pragma: no cover
    main()
