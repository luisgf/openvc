"""
10 — SD-JWT VC Type Metadata: an issuer pins the credential type with `vct#integrity`;
the verifier resolves the Type Metadata document, checks its integrity + `vct`, and
validates the disclosed claims against the type's `claims` metadata (path + mandatory).

The Type Metadata is served from an in-memory store here (in production a verifier
fetches it from the `vct` HTTPS URL through openvc's SSRF-guarded fetch —
`openvc.resolvers.default_type_metadata_resolver`).

Run:  python examples/10_sd_jwt_type_metadata.py
"""
import base64
import hashlib
import json

from _common import did_key_p256

from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.type_metadata import validate_type_metadata

VCT = "https://credentials.example.com/education_credential/v1"

# The type's published Type Metadata document (its `claims` drive validation).
type_metadata = {
    "vct": VCT,
    "name": "Example Education Credential",
    "claims": [
        {"path": ["name"], "sd": "always", "mandatory": True},
        {"path": ["degree"], "sd": "always"},
    ],
}
metadata_bytes = json.dumps(type_metadata).encode()
vct_integrity = "sha256-" + base64.b64encode(hashlib.sha256(metadata_bytes).digest()).decode()

# Issuer -> holder: an SD-JWT VC of that type, pinning the metadata with vct#integrity.
issuer, issuer_did = did_key_p256()
holder, _ = did_key_p256()
issued = SdJwtVcProofSuite().issue(
    {"iss": issuer_did, "vct#integrity": vct_integrity, "name": "Ada Lovelace",
     "degree": "Mathematics"},
    signing_key=issuer, vct=VCT, disclosable=["name", "degree"],
    holder_jwk=holder.public_jwk())

# Verifier: verify the SD-JWT VC, then process its Type Metadata.
verified = SdJwtVcProofSuite().verify(issued, public_key_jwk=issuer.public_jwk())
print("vct           :", verified.vct)

result = validate_type_metadata(
    verified.claims, vct=verified.vct,
    vct_integrity=verified.claims.get("vct#integrity"),
    resolve=lambda url: {VCT: metadata_bytes}[url])       # in-memory; real: fetch by URL

print("type name     :", result.documents[0]["name"])
print("claims checked :", [c["path"] for c in result.claims])
print("integrity + mandatory 'name' + paths validated ✓")
