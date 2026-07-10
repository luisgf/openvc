"""
tests/test_schema.py — credentialSchema (W3C VC JSON Schema) validation
(``openvc.schema`` + the ``resolve_credential_schema`` pipeline hook).

Parsing needs nothing; the validation and pipeline tests ``importorskip`` the
optional ``jsonschema`` processor (the ``[schema]`` extra). The schema fixture
mirrors the spec's Example 2 (an ``EmailCredential`` JsonSchema) — it constrains
``credentialSubject.emailAddress`` at the schema's top level, so the whole
credential is the validation instance.
"""
from __future__ import annotations

import json

import pytest

from openvc.did.base import DidResolutionError
from openvc.schema import (
    CredentialSchemaRef,
    SchemaResolutionError,
    SchemaUnavailable,
    SchemaValidationError,
    UnsupportedSchemaType,
    parse_credential_schemas,
    validate_credential_schema,
)

SCHEMA_URL = "https://example.com/schemas/email.json"


def _b(obj: object) -> bytes:
    """A resolve_credential_schema now returns raw bytes; serialise a test schema."""
    return json.dumps(obj).encode()


# Spec Example 2: a raw JSON Schema whose top-level `properties.credentialSubject`
# requires `emailAddress` — only bites if the whole VC is the instance.
EMAIL_SCHEMA = {
    "$id": SCHEMA_URL,
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "EmailCredential",
    "type": "object",
    "properties": {
        "credentialSubject": {
            "type": "object",
            "properties": {"emailAddress": {"type": "string", "format": "email"}},
            "required": ["emailAddress"],
        }
    },
}


def _cred(*, subject=None, credential_schema=None):
    c = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:1",
        "type": ["VerifiableCredential"],
        "issuer": "did:web:issuer.example",
        "credentialSubject": subject if subject is not None else {"emailAddress": "a@b.com"},
    }
    if credential_schema is not None:
        c["credentialSchema"] = credential_schema
    return c


def _entry(schema_type="JsonSchema", url=SCHEMA_URL, **extra):
    return {"id": url, "type": schema_type, **extra}


# --------------------------------------------------------------------------- #
# parse_credential_schemas — no jsonschema needed
# --------------------------------------------------------------------------- #

def test_parse_single_and_array():
    one = parse_credential_schemas(_cred(credential_schema=_entry()))
    assert one == [CredentialSchemaRef(id=SCHEMA_URL, type="JsonSchema")]
    two = parse_credential_schemas(_cred(credential_schema=[
        _entry(url="https://ex/a.json"), _entry(url="https://ex/b.json")]))
    assert [r.id for r in two] == ["https://ex/a.json", "https://ex/b.json"]


def test_parse_none_when_absent_or_empty():
    assert parse_credential_schemas(_cred()) == []
    assert parse_credential_schemas(_cred(credential_schema=[])) == []


def test_parse_captures_digest_sri():
    refs = parse_credential_schemas(
        _cred(credential_schema=_entry(digestSRI="sha384-abc")))
    assert refs[0].digest_sri == "sha384-abc"


def test_parse_type_as_list_picks_recognised():
    refs = parse_credential_schemas(
        _cred(credential_schema=_entry(schema_type=["SomethingElse", "JsonSchema"])))
    assert refs[0].type == "JsonSchema"


def test_parse_unknown_type_preserved():
    refs = parse_credential_schemas(
        _cred(credential_schema=_entry(schema_type="OtherSchema2099")))
    assert refs[0].type == "OtherSchema2099"


def test_parse_rejects_malformed_entries():
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(_cred(credential_schema={"type": "JsonSchema"}))  # no id
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(_cred(credential_schema={"id": SCHEMA_URL}))       # no type
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(_cred(credential_schema={"id": 42, "type": "JsonSchema"}))
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(_cred(credential_schema="not-an-object"))


# --------------------------------------------------------------------------- #
# validate_credential_schema — needs the jsonschema processor
# --------------------------------------------------------------------------- #

def test_validate_conforming_credential():
    pytest.importorskip("jsonschema")
    result = validate_credential_schema(
        _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))
    assert result.validated is True
    assert result.schemas == (SCHEMA_URL,)


def test_validate_nonconforming_raises():
    pytest.importorskip("jsonschema")
    cred = _cred(subject={"id": "did:example:s"},        # no emailAddress -> violates schema
                 credential_schema=_entry())
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(cred, resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))


def test_validate_no_schema_declared_is_noop():
    pytest.importorskip("jsonschema")
    result = validate_credential_schema(
        _cred(), resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))
    assert result.validated is False and result.schemas == ()


def test_validate_wrapper_shape_accepted():
    pytest.importorskip("jsonschema")
    # a resolver that hands back a {jsonSchema: ...} wrapper still works
    result = validate_credential_schema(
        _cred(credential_schema=_entry()),
        resolve_credential_schema=lambda u: _b({"jsonSchema": EMAIL_SCHEMA}))
    assert result.validated is True


def test_validate_json_schema_credential_type_unsupported():
    pytest.importorskip("jsonschema")
    with pytest.raises(UnsupportedSchemaType):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))


def test_validate_unknown_type_unsupported():
    pytest.importorskip("jsonschema")
    with pytest.raises(UnsupportedSchemaType):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="OtherSchema2099")),
            resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))


def test_validate_resolver_transport_error_wrapped():
    pytest.importorskip("jsonschema")

    def boom(_url):
        raise DidResolutionError("blocked by SSRF guard")

    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry()), resolve_credential_schema=boom)


def test_validate_non_dict_resource_rejected():
    pytest.importorskip("jsonschema")
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry()),
            resolve_credential_schema=lambda u: _b(["not", "a", "schema"]))


def test_validate_resource_without_schema_keyword_rejected():
    pytest.importorskip("jsonschema")
    no_dollar_schema = {k: v for k, v in EMAIL_SCHEMA.items() if k != "$schema"}
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry()),
            resolve_credential_schema=lambda u: _b(no_dollar_schema))


def test_validate_garbage_schema_rejected():
    pytest.importorskip("jsonschema")
    garbage = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": 123}
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: _b(garbage))


def test_validate_remote_ref_fails_closed_without_network(monkeypatch):
    pytest.importorskip("jsonschema")
    import urllib.request

    def _no_network(*a, **k):
        raise AssertionError("network must not be touched during schema validation")

    monkeypatch.setattr(urllib.request, "urlopen", _no_network)
    remote_ref_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"credentialSubject": {"$ref": "http://169.254.169.254/latest/meta-data/"}},
    }
    with pytest.raises(SchemaResolutionError):        # not AssertionError -> no urlopen
        validate_credential_schema(
            _cred(credential_schema=_entry()),
            resolve_credential_schema=lambda u: _b(remote_ref_schema))


def test_validate_local_ref_resolves():
    pytest.importorskip("jsonschema")
    local_ref_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "$defs": {"sub": {"type": "object", "required": ["emailAddress"]}},
        "properties": {"credentialSubject": {"$ref": "#/$defs/sub"}},
    }
    ok = validate_credential_schema(
        _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: _b(local_ref_schema))
    assert ok.validated is True
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(
            _cred(subject={"id": "x"}, credential_schema=_entry()),
            resolve_credential_schema=lambda u: _b(local_ref_schema))


def test_validate_deeply_nested_schema_fails_closed():
    pytest.importorskip("jsonschema")
    # A hostile, deeply-nested schema must fail closed as a typed SchemaError, not
    # leak a raw RecursionError. Build the deep JSON *bytes* by concatenation so the
    # test itself never recurses (json.dumps of a deep dict would RecursionError here).
    depth = 2000
    root_open = ('{"$schema":"https://json-schema.org/draft/2020-12/schema"'
                 ',"type":"object","properties":{"a":')
    level_open = '{"type":"object","properties":{"a":'
    raw = (root_open + level_open * (depth - 1)
           + '{"type":"object"}' + '}}' * (depth - 1) + '}}').encode()
    cred = _cred(credential_schema=_entry())
    with pytest.raises(SchemaResolutionError):        # RecursionError -> typed SchemaError
        validate_credential_schema(cred, resolve_credential_schema=lambda u: raw)


def test_parse_rejects_list_with_non_dict_member():
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(_cred(credential_schema=["garbage"]))
    with pytest.raises(SchemaResolutionError):
        parse_credential_schemas(_cred(credential_schema=[_entry(), 42]))


def test_validate_array_all_applied_and_one_failing():
    pytest.importorskip("jsonschema")
    name_schema = {
        "$id": "https://ex/name.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "credentialSubject": {"type": "object", "required": ["name"]}},
    }
    schemas = {SCHEMA_URL: EMAIL_SCHEMA, "https://ex/name.json": name_schema}
    cred = _cred(subject={"emailAddress": "a@b.com", "name": "Ada"},
                 credential_schema=[_entry(), _entry(url="https://ex/name.json")])
    result = validate_credential_schema(cred, resolve_credential_schema=lambda u: _b(schemas[u]))
    assert set(result.schemas) == set(schemas)
    # drop `name` -> the second schema fails
    cred_bad = _cred(subject={"emailAddress": "a@b.com"},
                     credential_schema=[_entry(), _entry(url="https://ex/name.json")])
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(cred_bad, resolve_credential_schema=lambda u: _b(schemas[u]))


# --------------------------------------------------------------------------- #
# digestSRI enforcement (issue #10)
# --------------------------------------------------------------------------- #

def _sri(data: bytes, alg: str = "sha384") -> str:
    import base64
    import hashlib
    h = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}[alg]
    return f"{alg}-{base64.b64encode(h(data).digest()).decode()}"


def test_validate_digest_sri_match():
    pytest.importorskip("jsonschema")
    raw = _b(EMAIL_SCHEMA)
    cred = _cred(credential_schema=_entry(digestSRI=_sri(raw)))
    result = validate_credential_schema(cred, resolve_credential_schema=lambda u: raw)
    assert result.validated is True


def test_validate_digest_sri_mismatch_fails_closed():
    pytest.importorskip("jsonschema")
    # SRI computed over different bytes than the resolver returns
    cred = _cred(credential_schema=_entry(digestSRI=_sri(b"a different schema")))
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(cred, resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))


def test_validate_digest_sri_malformed_rejected():
    pytest.importorskip("jsonschema")
    cred = _cred(credential_schema=_entry(digestSRI="not-a-real-sri"))
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(cred, resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))


def test_validate_digest_sri_strongest_alg_enforced():
    pytest.importorskip("jsonschema")
    raw = _b(EMAIL_SCHEMA)
    # a correct sha256 but a WRONG sha512 -> the strongest (sha512) must win -> reject
    sri = _sri(raw, "sha256") + " " + _sri(b"wrong", "sha512")
    cred = _cred(credential_schema=_entry(digestSRI=sri))
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(cred, resolve_credential_schema=lambda u: raw)


def test_validate_resolver_must_return_bytes():
    pytest.importorskip("jsonschema")
    with pytest.raises(SchemaResolutionError):     # a dict, not bytes
        validate_credential_schema(
            _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: EMAIL_SCHEMA)


# --------------------------------------------------------------------------- #
# JsonSchemaCredential (schema-in-a-VC) — unit level, with an injected verify_inner
# --------------------------------------------------------------------------- #

def _jsc(schema=EMAIL_SCHEMA, *, types=("VerifiableCredential", "JsonSchemaCredential"),
         subject=None):
    """A minimal *verified* JsonSchemaCredential document (what verify_inner returns):
    its credentialSubject nests the schema under `jsonSchema` (W3C VC JSON Schema §5)."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": SCHEMA_URL,
        "type": list(types),
        "issuer": "did:web:schema-authority.example",
        "credentialSubject": subject if subject is not None
        else {"id": SCHEMA_URL, "type": "JsonSchema", "jsonSchema": schema},
    }


def test_json_schema_credential_validated_via_verifier():
    pytest.importorskip("jsonschema")
    inner = _jsc()
    result = validate_credential_schema(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
        resolve_credential_schema=lambda u: b"<inner-vc-jwt-bytes>",
        verify_inner=lambda raw: inner)
    assert result.validated is True and result.schemas == (SCHEMA_URL,)


def test_json_schema_credential_nonconforming_raises():
    pytest.importorskip("jsonschema")
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(
            _cred(subject={"id": "did:example:s"},       # no emailAddress -> violates schema
                  credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: b"x", verify_inner=lambda raw: _jsc())


def test_json_schema_credential_no_verifier_is_unsupported():
    pytest.importorskip("jsonschema")
    # Standalone (no pipeline) API: a JsonSchemaCredential needs an injected verifier.
    with pytest.raises(UnsupportedSchemaType):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: b"x")


def test_json_schema_credential_inner_verify_failure_fails_closed():
    pytest.importorskip("jsonschema")
    from openvc import OpenvcError

    def _boom(_raw):
        raise OpenvcError("inner proof did not verify")

    with pytest.raises(SchemaResolutionError):        # inner failure -> resolution error
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: b"x", verify_inner=_boom)


def test_json_schema_credential_wrong_type_rejected():
    pytest.importorskip("jsonschema")
    # A signature-valid VC that is NOT a JsonSchemaCredential cannot stand in as the
    # schema authority, even though its proof verified.
    plain = _jsc(types=("VerifiableCredential",))
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: b"x", verify_inner=lambda raw: plain)


def test_json_schema_credential_missing_json_schema_rejected():
    pytest.importorskip("jsonschema")
    no_schema = _jsc(subject={"id": SCHEMA_URL, "type": "JsonSchema"})   # no jsonSchema
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: b"x", verify_inner=lambda raw: no_schema)


def test_json_schema_credential_subject_array_picks_json_schema():
    pytest.importorskip("jsonschema")
    # VCDM allows an array of credentialSubject; the JsonSchema one is selected.
    multi = _jsc(subject=[{"id": "did:example:other"},
                          {"id": SCHEMA_URL, "type": "JsonSchema", "jsonSchema": EMAIL_SCHEMA}])
    result = validate_credential_schema(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
        resolve_credential_schema=lambda u: b"x", verify_inner=lambda raw: multi)
    assert result.validated is True


def test_json_schema_credential_verify_inner_receives_raw_bytes():
    pytest.importorskip("jsonschema")
    seen = {}

    def _capture(raw):
        seen["raw"] = raw
        return _jsc()

    validate_credential_schema(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
        resolve_credential_schema=lambda u: b"the-exact-fetched-bytes", verify_inner=_capture)
    assert seen["raw"] == b"the-exact-fetched-bytes"


def test_json_schema_credential_digest_sri_enforced_over_vc_bytes():
    pytest.importorskip("jsonschema")
    raw = b"the-schema-credential-bytes"
    # a matching SRI passes and verify_inner runs
    ok = validate_credential_schema(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential", digestSRI=_sri(raw))),
        resolve_credential_schema=lambda u: raw, verify_inner=lambda r: _jsc())
    assert ok.validated is True
    # a mismatching SRI fails closed BEFORE verify_inner is ever called
    called = {"n": 0}

    def _count(_raw):
        called["n"] += 1
        return _jsc()

    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry(
                schema_type="JsonSchemaCredential", digestSRI=_sri(b"different"))),
            resolve_credential_schema=lambda u: raw, verify_inner=_count)
    assert called["n"] == 0                     # SRI gate fired before the inner verify


# --------------------------------------------------------------------------- #
# Pipeline integration — verify_credential(resolve_credential_schema=...)
# --------------------------------------------------------------------------- #

def _registry(did, vm_id, jwk):
    """A minimal in-test DID registry (self-contained: no cross-test import)."""
    from openvc.did.base import DidResolutionError, parse_did_document
    doc = parse_did_document({
        "id": did,
        "verificationMethod": [
            {"id": vm_id, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
    })

    class _Reg:
        def supports(self, d):
            return d == did

        def resolve(self, d):
            if d != did:
                raise DidResolutionError(f"unknown DID {d!r}")
            return doc

    return _Reg()


def _signed(cred):
    from openvc.keys import P256SigningKey
    from openvc.proof.vc_jwt import VcJwtProofSuite
    vm = "did:web:issuer.example#key-1"
    sk = P256SigningKey.generate(kid=vm)
    token = VcJwtProofSuite().sign(cred, signing_key=sk)
    return token, _registry("did:web:issuer.example", vm, sk.public_jwk())


def test_pipeline_validates_when_resolver_given():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential
    token, reg = _signed(_cred(credential_schema=_entry()))
    result = verify_credential(
        token, resolver=reg, resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))
    assert result.schema is not None and result.schema.validated is True


def test_pipeline_rejects_nonconforming():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential
    token, reg = _signed(_cred(subject={"id": "did:example:s"}, credential_schema=_entry()))
    with pytest.raises(SchemaValidationError):
        verify_credential(token, resolver=reg, resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))


def test_pipeline_opt_in_by_default():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential
    # declared schema, no resolver, default policy -> not checked, verifies fine
    token, reg = _signed(_cred(subject={"id": "did:example:s"}, credential_schema=_entry()))
    result = verify_credential(token, resolver=reg)
    assert result.schema is None


def test_pipeline_require_schema_fails_closed():
    pytest.importorskip("jsonschema")
    from openvc import VerificationPolicy, verify_credential
    token, reg = _signed(_cred(credential_schema=_entry()))
    with pytest.raises(SchemaUnavailable):
        verify_credential(token, resolver=reg,
                          policy=VerificationPolicy(require_schema=True))


def test_pipeline_resolver_but_no_schema_declared():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential
    token, reg = _signed(_cred())                 # no credentialSchema
    result = verify_credential(
        token, resolver=reg, resolve_credential_schema=lambda u: _b(EMAIL_SCHEMA))
    assert result.schema is None


# --------------------------------------------------------------------------- #
# JsonSchemaCredential end-to-end through verify_credential (real signatures)
# --------------------------------------------------------------------------- #

def _multi_registry(entries):
    """A DID registry resolving several DIDs (self-contained, no cross-test import)."""
    from openvc.did.base import DidResolutionError, parse_did_document
    docs = {
        did: parse_did_document({
            "id": did,
            "verificationMethod": [
                {"id": vm, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk}],
            "assertionMethod": [vm],
            "authentication": [vm],
        })
        for did, vm, jwk in entries
    }

    class _Reg:
        def supports(self, d):
            return d in docs

        def resolve(self, d):
            if d not in docs:
                raise DidResolutionError(f"unknown DID {d!r}")
            return docs[d]

    return _Reg()


def _vc_jwt(cred, did):
    """Sign *cred* as a VC-JWT under a fresh key at ``did#key-1``; return (token, entry)."""
    from openvc.keys import P256SigningKey
    from openvc.proof.vc_jwt import VcJwtProofSuite
    vm = f"{did}#key-1"
    sk = P256SigningKey.generate(kid=vm)
    return VcJwtProofSuite().sign(cred, signing_key=sk), (did, vm, sk.public_jwk())


def _schema_credential_doc(schema=EMAIL_SCHEMA):
    """A JsonSchemaCredential VC (the JSON Schema wrapped in its own VC), pre-signature.
    Its own ``credentialSchema`` points at the meta-schema — the pipeline must NOT
    recurse into it, so that URL is never fetched."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": SCHEMA_URL,
        "type": ["VerifiableCredential", "JsonSchemaCredential"],
        "issuer": "did:web:schema-authority.example",
        "credentialSchema": {
            "id": "https://www.w3.org/ns/credentials/json-schema/v2.json",
            "type": "JsonSchema"},
        "credentialSubject": {"id": SCHEMA_URL, "type": "JsonSchema", "jsonSchema": schema},
    }


_SCHEMA_DID = "did:web:schema-authority.example"
_ISSUER_DID = "did:web:issuer.example"


def test_pipeline_json_schema_credential_end_to_end():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential

    inner_token, inner_entry = _vc_jwt(_schema_credential_doc(), _SCHEMA_DID)
    outer_token, outer_entry = _vc_jwt(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")), _ISSUER_DID)
    reg = _multi_registry([inner_entry, outer_entry])

    fetched = []

    def _resolve(url):
        fetched.append(url)
        return inner_token.encode()

    result = verify_credential(outer_token, resolver=reg, resolve_credential_schema=_resolve)
    assert result.schema is not None and result.schema.validated is True
    assert result.schema.schemas == (SCHEMA_URL,)
    # the schema-VC's OWN credentialSchema (the meta-schema) was never fetched -> bounded
    assert fetched == [SCHEMA_URL]


def test_pipeline_json_schema_credential_rejects_nonconforming():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential

    inner_token, inner_entry = _vc_jwt(_schema_credential_doc(), _SCHEMA_DID)
    outer_token, outer_entry = _vc_jwt(
        _cred(subject={"id": "did:example:s"},            # no emailAddress -> violates schema
              credential_schema=_entry(schema_type="JsonSchemaCredential")), _ISSUER_DID)
    reg = _multi_registry([inner_entry, outer_entry])
    with pytest.raises(SchemaValidationError):
        verify_credential(outer_token, resolver=reg,
                          resolve_credential_schema=lambda u: inner_token.encode())


def test_pipeline_json_schema_credential_tampered_inner_fails_closed():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential

    inner_token, inner_entry = _vc_jwt(_schema_credential_doc(), _SCHEMA_DID)
    outer_token, outer_entry = _vc_jwt(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")), _ISSUER_DID)
    reg = _multi_registry([inner_entry, outer_entry])
    # tamper the FIRST signature char (top 6 bits of byte 0 — always fully significant)
    # so the inner proof cannot verify. Flipping the LAST base64 char is flaky: it can
    # land on the final byte's don't-care padding bits and leave the signature unchanged.
    head, payload, sig = inner_token.split(".")
    tampered = ".".join([head, payload, ("A" if sig[0] != "A" else "B") + sig[1:]])
    with pytest.raises(SchemaResolutionError):
        verify_credential(outer_token, resolver=reg,
                          resolve_credential_schema=lambda u: tampered.encode())


def test_pipeline_json_schema_credential_unresolvable_inner_issuer_fails_closed():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential

    inner_token, _inner_entry = _vc_jwt(_schema_credential_doc(), _SCHEMA_DID)
    outer_token, outer_entry = _vc_jwt(
        _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")), _ISSUER_DID)
    # the registry knows ONLY the outer issuer -> the inner schema-VC's key can't resolve
    reg = _multi_registry([outer_entry])
    with pytest.raises(SchemaResolutionError):
        verify_credential(outer_token, resolver=reg,
                          resolve_credential_schema=lambda u: inner_token.encode())
