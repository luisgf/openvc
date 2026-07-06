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
        _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: EMAIL_SCHEMA)
    assert result.validated is True
    assert result.schemas == (SCHEMA_URL,)


def test_validate_nonconforming_raises():
    pytest.importorskip("jsonschema")
    cred = _cred(subject={"id": "did:example:s"},        # no emailAddress -> violates schema
                 credential_schema=_entry())
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(cred, resolve_credential_schema=lambda u: EMAIL_SCHEMA)


def test_validate_no_schema_declared_is_noop():
    pytest.importorskip("jsonschema")
    result = validate_credential_schema(_cred(), resolve_credential_schema=lambda u: EMAIL_SCHEMA)
    assert result.validated is False and result.schemas == ()


def test_validate_wrapper_shape_accepted():
    pytest.importorskip("jsonschema")
    # a resolver that hands back a {jsonSchema: ...} wrapper still works
    result = validate_credential_schema(
        _cred(credential_schema=_entry()),
        resolve_credential_schema=lambda u: {"jsonSchema": EMAIL_SCHEMA})
    assert result.validated is True


def test_validate_json_schema_credential_type_unsupported():
    pytest.importorskip("jsonschema")
    with pytest.raises(UnsupportedSchemaType):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="JsonSchemaCredential")),
            resolve_credential_schema=lambda u: EMAIL_SCHEMA)


def test_validate_unknown_type_unsupported():
    pytest.importorskip("jsonschema")
    with pytest.raises(UnsupportedSchemaType):
        validate_credential_schema(
            _cred(credential_schema=_entry(schema_type="OtherSchema2099")),
            resolve_credential_schema=lambda u: EMAIL_SCHEMA)


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
            resolve_credential_schema=lambda u: ["not", "a", "schema"])


def test_validate_resource_without_schema_keyword_rejected():
    pytest.importorskip("jsonschema")
    no_dollar_schema = {k: v for k, v in EMAIL_SCHEMA.items() if k != "$schema"}
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry()),
            resolve_credential_schema=lambda u: no_dollar_schema)


def test_validate_garbage_schema_rejected():
    pytest.importorskip("jsonschema")
    garbage = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": 123}
    with pytest.raises(SchemaResolutionError):
        validate_credential_schema(
            _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: garbage)


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
            resolve_credential_schema=lambda u: remote_ref_schema)


def test_validate_local_ref_resolves():
    pytest.importorskip("jsonschema")
    local_ref_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "$defs": {"sub": {"type": "object", "required": ["emailAddress"]}},
        "properties": {"credentialSubject": {"$ref": "#/$defs/sub"}},
    }
    ok = validate_credential_schema(
        _cred(credential_schema=_entry()), resolve_credential_schema=lambda u: local_ref_schema)
    assert ok.validated is True
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(
            _cred(subject={"id": "x"}, credential_schema=_entry()),
            resolve_credential_schema=lambda u: local_ref_schema)


def test_validate_deeply_nested_schema_fails_closed():
    pytest.importorskip("jsonschema")
    # a schema nested past the recursion limit must fail closed as a typed
    # SchemaError, not leak a raw RecursionError out of the pipeline.
    schema: dict = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}
    inst: dict = {}
    snode, inode = schema, inst
    for _ in range(2000):
        schild: dict = {"type": "object"}
        snode["properties"] = {"a": schild}
        snode = schild
        ichild: dict = {}
        inode["a"] = ichild
        inode = ichild
    cred = _cred(credential_schema=_entry())
    cred["a"] = inst["a"]
    with pytest.raises(SchemaResolutionError):        # RecursionError -> typed SchemaError
        validate_credential_schema(cred, resolve_credential_schema=lambda u: schema)


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
    result = validate_credential_schema(cred, resolve_credential_schema=lambda u: schemas[u])
    assert set(result.schemas) == set(schemas)
    # drop `name` -> the second schema fails
    cred_bad = _cred(subject={"emailAddress": "a@b.com"},
                     credential_schema=[_entry(), _entry(url="https://ex/name.json")])
    with pytest.raises(SchemaValidationError):
        validate_credential_schema(cred_bad, resolve_credential_schema=lambda u: schemas[u])


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
        token, resolver=reg, resolve_credential_schema=lambda u: EMAIL_SCHEMA)
    assert result.schema is not None and result.schema.validated is True


def test_pipeline_rejects_nonconforming():
    pytest.importorskip("jsonschema")
    from openvc import verify_credential
    token, reg = _signed(_cred(subject={"id": "did:example:s"}, credential_schema=_entry()))
    with pytest.raises(SchemaValidationError):
        verify_credential(token, resolver=reg, resolve_credential_schema=lambda u: EMAIL_SCHEMA)


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
        token, resolver=reg, resolve_credential_schema=lambda u: EMAIL_SCHEMA)
    assert result.schema is None
