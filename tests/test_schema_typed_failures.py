"""
tests/test_schema_typed_failures.py — every failure the ``jsonschema`` processor lets
escape while a credential is validated against its ``credentialSchema`` is a typed
``SchemaError`` (#387; found by the internal security review of 2026-11-07, § M11).

On v1.38.1 the dialect lookup (``validator_for``) ran outside the guarded region of
``openvc.schema._validate_instance`` and the guard caught only the processor's own
types and ``RecursionError``. Four measured inputs escaped as bare exceptions — and,
because ``verify_many`` isolates items with ``except OpenvcError``, each aborted a
whole batch:

| schema keyword / credential value                       | bare exception on main        |
|---------------------------------------------------------|-------------------------------|
| ``multipleOf: 0.5`` + the number ``1e400`` (infinity)   | ``OverflowError`` (multipleOf)|
| ``multipleOf: 0.5`` + a 400-digit integer               | ``OverflowError`` (multipleOf)|
| ``multipleOf: <400-digit integer>`` + a float           | ``OverflowError`` (multipleOf)|
| ``"$schema": "http://[::1"``                            | ``ValueError`` (urlsplit)     |

Now the lookup runs inside the guard and the bare types are caught, attributed by the
phase they surfaced in: the schema's while it is looked up and built
(``SchemaResolutionError``), the credential's while it is validated
(``SchemaValidationError``). Every test here needs the ``[schema]`` extra and
``importorskip``s it, like ``test_schema.py``; the helpers are copied from there
(``tests/`` is not a package). Credentials and schemas are parsed from JSON *text* so
``1e400`` and the 400-digit integer reach the processor exactly as they would off the
wire.
"""
from __future__ import annotations

import asyncio
import json
import re

import pytest

from openvc.schema import (
    SchemaResolutionError,
    SchemaValidationError,
    validate_credential_schema,
    validate_credential_schema_async,
)

DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_URL = "https://schemas.example/s.json"
BIG = "1" + "0" * 400          # an integer no float can hold


def _schema_bytes(n_keyword: str) -> bytes:
    """A draft 2020-12 schema constraining ``credentialSubject.n`` with *n_keyword*."""
    return (
        '{"$schema": "%s", "properties": {"credentialSubject": '
        '{"properties": {"n": %s}}}}' % (DIALECT, n_keyword)
    ).encode()


def _cred(n_json: str, *, schema_type: str = "JsonSchema", url: str = SCHEMA_URL) -> dict:
    """A VCDM 2.0 credential whose subject carries the number *n_json*, declaring one
    ``credentialSchema`` entry. Parsed from text so the number is read as the wire would."""
    return json.loads(
        '{"@context": ["https://www.w3.org/ns/credentials/v2"], "id": "urn:uuid:1", '
        '"type": ["VerifiableCredential"], "issuer": "did:web:issuer.example", '
        '"credentialSubject": {"n": %s}, '
        '"credentialSchema": {"id": "%s", "type": "%s"}}' % (n_json, url, schema_type))


# The four measured rows: (schema bytes, the credential's number as JSON text, the typed
# class the failure must become, the bare exception it was on main).
_ROWS = [
    pytest.param(_schema_bytes('{"multipleOf": 0.5}'), "1e400",
                 SchemaValidationError, OverflowError,
                 id="multipleOf-float-vs-infinite-number"),
    pytest.param(_schema_bytes('{"multipleOf": 0.5}'), BIG,
                 SchemaValidationError, OverflowError,
                 id="multipleOf-float-vs-400-digit-integer"),
    pytest.param(_schema_bytes('{"multipleOf": %s}' % BIG), "1.5",
                 SchemaValidationError, OverflowError,
                 id="multipleOf-400-digit-integer-vs-float"),
    pytest.param(b'{"$schema": "http://[::1", "type": "object"}', "1",
                 SchemaResolutionError, ValueError,
                 id="dialect-uri-urlsplit-rejects"),
]


# --------------------------------------------------------------------------- #
# Unit level — validate_credential_schema with an in-test resolver
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("schema, n, typed, bare", _ROWS)
def test_what_the_processor_lets_escape_is_a_typed_schema_error(schema, n, typed, bare):
    pytest.importorskip("jsonschema")
    with pytest.raises(typed) as info:
        validate_credential_schema(_cred(n), resolve_credential_schema=lambda u: schema)
    assert type(info.value) is typed                     # the exact class, not a sibling
    assert type(info.value.__cause__) is bare            # chained from the processor's own
    assert bare.__name__ in str(info.value)              # ... and named in the message
    assert SCHEMA_URL in str(info.value)


def test_the_schema_side_failure_is_attributed_before_any_validation():
    """The ``$schema`` row fails while the dialect is looked up — the resource is unusable
    (``SchemaResolutionError``), not "the credential does not conform"."""
    pytest.importorskip("jsonschema")
    with pytest.raises(SchemaResolutionError) as info:
        validate_credential_schema(
            _cred("1"),
            resolve_credential_schema=lambda u: b'{"$schema": "http://[::1", "type": "object"}')
    assert "could not be processed as a JSON Schema" in str(info.value)
    assert "ValueError" in str(info.value)


def test_the_instance_side_failure_is_attributed_to_the_credential():
    """The ``multipleOf`` rows fail while the credential's value is checked: the
    credential could not be validated (``SchemaValidationError``)."""
    pytest.importorskip("jsonschema")
    with pytest.raises(SchemaValidationError) as info:
        validate_credential_schema(
            _cred("1e400"),
            resolve_credential_schema=lambda u: _schema_bytes('{"multipleOf": 0.5}'))
    assert "could not validate against schema" in str(info.value)
    assert "OverflowError" in str(info.value)


def test_the_same_schema_still_validates_an_ordinary_number():
    """Control: the schema shapes above are legitimate; only the hostile value fails."""
    pytest.importorskip("jsonschema")
    result = validate_credential_schema(
        _cred("1"), resolve_credential_schema=lambda u: _schema_bytes('{"multipleOf": 0.5}'))
    assert result.validated is True and result.schemas == (SCHEMA_URL,)


def test_the_async_lane_shares_the_typed_guard():
    pytest.importorskip("jsonschema")

    async def resolve(url: str) -> bytes:
        return _schema_bytes('{"multipleOf": 0.5}')

    async def run():
        await validate_credential_schema_async(_cred("1e400"), resolve_credential_schema=resolve)

    with pytest.raises(SchemaValidationError) as info:
        asyncio.run(run())
    assert type(info.value.__cause__) is OverflowError


# --------------------------------------------------------------------------- #
# The whole tuple and both phases, pinned with a processor made to raise each type
# --------------------------------------------------------------------------- #

_BARE = [ValueError, TypeError, OverflowError, ZeroDivisionError, re.error]


@pytest.mark.parametrize("bare", _BARE, ids=lambda c: c.__name__)
def test_every_bare_type_raised_while_building_is_a_resolution_error(monkeypatch, bare):
    jsonschema = pytest.importorskip("jsonschema")

    def boom(schema, default=None):
        raise bare("x" * 10_000)

    monkeypatch.setattr(jsonschema.validators, "validator_for", boom)
    with pytest.raises(SchemaResolutionError) as info:
        validate_credential_schema(
            _cred("1"), resolve_credential_schema=lambda u: _schema_bytes('{"type": "number"}'))
    assert type(info.value.__cause__) is bare
    assert bare.__name__ in str(info.value)
    assert len(str(info.value)) < 400                   # the processor's text is cut (safe_repr)


@pytest.mark.parametrize("bare", _BARE, ids=lambda c: c.__name__)
def test_every_bare_type_raised_while_validating_is_a_validation_error(monkeypatch, bare):
    pytest.importorskip("jsonschema")
    from jsonschema import Draft202012Validator
    real = Draft202012Validator.iter_errors

    def boom(self, instance, *args, **kwargs):
        # check_schema meta-validates the SCHEMA through this same method (the build
        # phase); only the credential's own validation is made to raise.
        if isinstance(instance, dict) and "credentialSubject" in instance:
            raise bare("x" * 10_000)
        return real(self, instance, *args, **kwargs)

    monkeypatch.setattr(Draft202012Validator, "iter_errors", boom)
    with pytest.raises(SchemaValidationError) as info:
        validate_credential_schema(
            _cred("1"), resolve_credential_schema=lambda u: _schema_bytes('{"type": "number"}'))
    assert type(info.value.__cause__) is bare
    assert bare.__name__ in str(info.value)
    assert len(str(info.value)) < 400


def test_a_recursion_overflow_in_the_processor_is_still_a_resolution_error():
    """Regression guard (passes on main too): a schema deep enough to overflow the
    processor's recursion is the schema's fault wherever it surfaces. The bytes form never
    gets this far (the bounded JSON loader refuses it first), so the dict form is handed
    over the way a ``JsonSchemaCredential``'s verified ``jsonSchema`` would be."""
    pytest.importorskip("jsonschema")
    deep: dict = {"type": "object"}
    for _ in range(5000):
        deep = {"type": "object", "properties": {"credentialSubject": deep}}
    deep["$schema"] = DIALECT
    schema_vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"], "id": SCHEMA_URL,
        "type": ["VerifiableCredential", "JsonSchemaCredential"],
        "issuer": "did:web:schema-authority.example",
        "credentialSubject": {"id": SCHEMA_URL, "type": "JsonSchema", "jsonSchema": deep},
    }
    with pytest.raises(SchemaResolutionError) as info:
        validate_credential_schema(
            _cred("1", schema_type="JsonSchemaCredential"),
            resolve_credential_schema=lambda u: b"<a signed schema VC>",
            verify_inner=lambda raw: schema_vc)          # an already-verified stand-in
    assert type(info.value.__cause__) is RecursionError


# --------------------------------------------------------------------------- #
# Through the pipeline — verify_credential / verify_many (real signatures)
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


def _signed_batch(*creds):
    """Sign every credential as a VC-JWT under ONE fresh issuer key; return the tokens
    and the registry resolving that issuer."""
    from openvc.keys import P256SigningKey
    from openvc.proof.vc_jwt import VcJwtProofSuite
    vm = "did:web:issuer.example#key-1"
    sk = P256SigningKey.generate(kid=vm)
    suite = VcJwtProofSuite()
    tokens = [suite.sign(c, signing_key=sk) for c in creds]
    return tokens, _registry("did:web:issuer.example", vm, sk.public_jwk())


@pytest.mark.parametrize("schema, n, typed, bare", _ROWS)
def test_verify_credential_raises_the_typed_error(schema, n, typed, bare):
    pytest.importorskip("jsonschema")
    from openvc import verify_credential
    (token,), reg = _signed_batch(_cred(n))
    with pytest.raises(typed) as info:
        verify_credential(token, resolver=reg, resolve_credential_schema=lambda u: schema)
    assert type(info.value) is typed
    assert type(info.value.__cause__) is bare


HONEST_URL = "https://schemas.example/honest.json"


@pytest.mark.parametrize("schema, n, typed, bare", _ROWS)
def test_verify_many_isolates_the_item_and_finishes_the_batch(schema, n, typed, bare):
    """The audit's measurement: on main the bare exception aborted the whole call. Now the
    hostile item is that item's ``error`` and its honest neighbours verify. The hostile
    credential points at the hostile schema (the issuer's own host, as in the attack); the
    honest ones declare a sane schema at another URL."""
    pytest.importorskip("jsonschema")
    from openvc import verify_many
    served = {SCHEMA_URL: schema, HONEST_URL: _schema_bytes('{"type": "integer"}')}
    (good, hostile, also_good), reg = _signed_batch(
        _cred("1", url=HONEST_URL), _cred(n), _cred("2", url=HONEST_URL))
    results = verify_many([good, hostile, also_good], resolver=reg,
                          resolve_credential_schema=served.__getitem__)
    assert [r.index for r in results] == [0, 1, 2]
    assert results[0].ok and results[0].result is not None
    assert results[2].ok and results[2].result is not None
    assert not results[1].ok and results[1].result is None
    assert type(results[1].error) is typed
    assert type(results[1].error.__cause__) is bare
