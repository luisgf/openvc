"""
openvc.schema — validate a credential against its ``credentialSchema`` (W3C VC
JSON Schema).

A credential may declare one or more JSON Schemas it claims to conform to via the
``credentialSchema`` property (VCDM 2.0 + the *Verifiable Credentials JSON Schema
Specification*). The ``JsonSchema`` type points ``id`` at a URL that dereferences
to a JSON Schema; the whole credential document is then validated against it.

**This check is opt-in, not fail-closed by default.** Unlike revocation status,
schema conformance is a *data-shape* property, not a security gate: a
signature-valid credential whose shape violates its schema is a malformed issue,
not a forgery. So the pipeline validates only when the caller supplies a
``resolve_credential_schema`` fetch. Set ``policy.require_schema=True`` to make a
credential that *declares* a ``credentialSchema`` but is verified without a
resolver fail (symmetric with ``require_status``). Once you *do* opt in, every
part of the check is fail-closed — an unreachable schema, a resource that is not a
valid JSON Schema, an unsupported schema type, or a validation error all raise.

**Transport is the caller's concern.** ``resolve_credential_schema`` takes a URL
and returns the parsed JSON Schema resource as a dict; pass
:func:`openvc.fetch.https_json_fetch` for the SSRF-guarded one (the same guard
``did:web`` uses). This module never opens a socket. Remote ``$ref`` resolution
inside a fetched schema is **off**: the validator is built with an *empty*
``referencing.Registry`` (no retrieve hook), so a remote ``$ref`` fails closed as
:class:`SchemaResolutionError` with no network call — whereas ``jsonschema``'s
*default* registry would ``urllib.urlopen`` an unresolvable remote ``$ref``, an
SSRF vector, since the schema body is attacker-influenced. Local (``#/…``) refs
still resolve against the schema document itself.

**Security caveat — untrusted schemas can be a ReDoS vector.** A fetched schema
is attacker-influenced (the issuer names ``credentialSchema.id``). JSON Schema
``pattern`` keywords run on Python's backtracking ``re`` engine, so a schema
carrying a catastrophic-backtracking regex can burn unbounded CPU during
validation. There is no clean dependency-light in-process bound (a hard timeout
needs a subprocess; a linear-time engine needs ``re2``); a very deep schema is
capped only by the recursion limit (surfaced as :class:`SchemaResolutionError`).
Point ``resolve_credential_schema`` at schema hosts you trust, or bound the work
in the injected fetch. Validation being **opt-in** limits exposure.

**Dependency-light:** the JSON Schema processor (``jsonschema``) lives behind the
``[schema]`` extra and is imported lazily. Without it, a credential that requires
schema validation raises :class:`SchemaBackendUnavailable` — the rest of the
library keeps working.

Only the ``JsonSchema`` type is validated here. ``JsonSchemaCredential`` (the
schema wrapped in its own Verifiable Credential, requiring a recursive VC
verification) is recognised but raises :class:`UnsupportedSchemaType`, so a
declared schema is never silently skipped when you asked for it to be checked.

**Spec notes** (W3C VC JSON Schema, CR Draft 2025-02-04):

* The whole credential document is the validation instance (schemas key into
  ``credentialSubject`` at their own top level); we never pre-extract the subject.
* The dialect follows the schema's ``$schema`` (draft 2020-12 is the required
  one). A resource with no ``$schema`` "MUST NOT be processed" — we reject it.
* ``format`` keywords (e.g. ``email``) are treated as annotations, not
  assertions — JSON Schema's default; we do not pull in format libraries.
* ``digestSRI`` on an entry is **enforced**: the resolver returns the raw schema
  bytes, and a ``sha256-``/``sha384-``/``sha512-`` SRI hash is verified over them
  (constant-time) before the schema is parsed — a mismatch fails closed. An issuer
  can thus pin the exact schema so even a compromised schema host cannot swap it.
* The spec models the outcome as Success / Failure / *Indeterminate*; this
  fail-closed verifier collapses Indeterminate (unreachable / non-schema /
  unsupported) into a raised :class:`SchemaError` rather than a distinct value.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Callable

from .errors import OpenvcError

# Fetch a schema URL -> the RAW schema bytes. Bytes (not a parsed dict) so a
# credentialSchema `digestSRI` can be verified over the exact response before parsing.
# The caller owns transport and the SSRF policy for that host (as with ResolveStatusList).
ResolveCredentialSchema = Callable[[str], bytes]

SCHEMA_TYPE_JSON = "JsonSchema"
SCHEMA_TYPE_JSON_CREDENTIAL = "JsonSchemaCredential"
_KNOWN_SCHEMA_TYPES = frozenset({SCHEMA_TYPE_JSON, SCHEMA_TYPE_JSON_CREDENTIAL})


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class SchemaError(OpenvcError):
    """Base class for every ``credentialSchema`` validation failure."""


class SchemaBackendUnavailable(SchemaError):
    """Schema validation was required but the ``jsonschema`` processor is not
    installed (``pip install openvc-core[schema]``)."""


class SchemaUnavailable(SchemaError):
    """The credential declares a ``credentialSchema`` but no
    ``resolve_credential_schema`` was supplied and ``require_schema`` is set
    (fail-closed, symmetric with :class:`~openvc.verify.StatusUnavailable`)."""


class SchemaResolutionError(SchemaError):
    """The schema could not be fetched, or the fetched resource is not a usable
    JSON Schema (bad transport, not JSON, or not a valid schema)."""


class UnsupportedSchemaType(SchemaError):
    """A declared ``credentialSchema`` entry has a type this verifier cannot
    validate (e.g. ``JsonSchemaCredential``)."""


class SchemaValidationError(SchemaError):
    """The credential does not conform to a declared JSON Schema."""


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CredentialSchemaRef:
    """One parsed ``credentialSchema`` entry."""
    id: str                        # URL that dereferences to the schema (resource)
    type: str                      # the recognised schema type, e.g. "JsonSchema"
    digest_sri: str | None = None  # optional subresource-integrity hash (not enforced)


@dataclass(frozen=True)
class SchemaValidationResult:
    """The outcome of validating a credential against its declared schema(s)."""
    validated: bool                       # True if at least one JsonSchema was applied
    schemas: tuple[str, ...]              # the schema URLs validated against


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _as_entry_list(raw: Any) -> list[dict]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        # Fail closed on a malformed list (any non-dict member) rather than filter
        # it away: a truthy `credentialSchema` counts as "declared" to the pipeline,
        # so silently dropping junk would let it pass `require_schema` unchecked.
        if not all(isinstance(e, dict) for e in raw):
            raise SchemaResolutionError("credentialSchema entries must be objects")
        return list(raw)
    raise SchemaResolutionError("credentialSchema must be an object or an array")


def parse_credential_schemas(credential: dict[str, Any]) -> list[CredentialSchemaRef]:
    """Parse the credential's ``credentialSchema`` property into typed refs.

    Each entry needs an ``id`` (the schema URL) and a ``type``. The recognised
    type (``JsonSchema`` / ``JsonSchemaCredential``) is kept; an entry whose type
    is none of those is preserved with its first declared type so the caller can
    decide (the pipeline treats an unknown type as unsupported when opted in)."""
    refs: list[CredentialSchemaRef] = []
    for raw in _as_entry_list(credential.get("credentialSchema")):
        sid = raw.get("id")
        stype = raw.get("type")
        if not isinstance(sid, str) or not sid:
            raise SchemaResolutionError("credentialSchema entry needs a string id")
        types = [stype] if isinstance(stype, str) else stype
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise SchemaResolutionError("credentialSchema entry needs a type")
        # Prefer a recognised type; otherwise keep the first declared one.
        recognised = next((t for t in types if t in _KNOWN_SCHEMA_TYPES), None)
        chosen = recognised if recognised is not None else (types[0] if types else "")
        if not chosen:
            raise SchemaResolutionError("credentialSchema entry needs a type")
        sri = raw.get("digestSRI")
        refs.append(CredentialSchemaRef(
            id=sid, type=chosen,
            digest_sri=sri if isinstance(sri, str) else None))
    return refs


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def _extract_json_schema(resource: dict[str, Any]) -> dict[str, Any]:
    """Return the JSON Schema from a dereferenced ``JsonSchema`` resource.

    The *Verifiable Credentials JSON Schema Specification* has the ``id`` of a
    ``JsonSchema`` entry dereference to a raw JSON Schema document. We also accept
    a resource that *wraps* the schema under a ``jsonSchema`` property (the shape
    ``JsonSchemaCredential`` uses for its embedded schema), so a caller that hands
    back either shape works. Anything else is a resolution error."""
    embedded = resource.get("jsonSchema")
    if isinstance(embedded, dict):
        return embedded
    return resource


def _validate_instance(instance: dict[str, Any], schema: dict[str, Any],
                       schema_url: str) -> None:
    """Validate *instance* against *schema*, raising :class:`SchemaValidationError`
    on any mismatch. The validator dialect follows the schema's ``$schema`` (JSON
    Schema draft 2020-12 by default). No remote ``$ref`` fetching is wired, so an
    unresolvable remote ``$ref`` fails closed. ``format`` keywords are treated as
    annotations (JSON Schema's default), not assertions."""
    try:
        import jsonschema
        import referencing
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError as JsonSchemaError
        from jsonschema.exceptions import ValidationError as JsonValidationError
        from referencing.exceptions import Unresolvable
    except ImportError as exc:  # pragma: no cover - exercised via SchemaBackendUnavailable
        raise SchemaBackendUnavailable(
            "credentialSchema validation needs the jsonschema processor: "
            "pip install openvc-core[schema]") from exc

    # W3C VC JSON Schema §4 (normative): "Schemas without a $schema property are
    # not considered valid and MUST NOT be processed." Enforce it rather than let
    # validator_for silently default the dialect.
    if not isinstance(schema.get("$schema"), str):
        raise SchemaResolutionError(
            f"resource at {schema_url!r} has no $schema and MUST NOT be processed")

    validator_cls = jsonschema.validators.validator_for(
        schema, default=Draft202012Validator)

    # Meta-validate, build, and run under one guard so every failure from the
    # attacker-influenced schema stays a typed SchemaError (SchemaError ->
    # OpenvcError contract). A deep schema can blow the recursion limit in either
    # check_schema or iter_errors, so RecursionError is caught across the whole
    # region, not just validation. The EMPTY `referencing.Registry` (no retrieve
    # hook) makes a remote `$ref` fail closed as Unresolvable with NO network call
    # — jsonschema's *default* registry would urllib.urlopen it, an SSRF vector.
    # Local (#/…) refs still resolve against the schema document itself.
    try:
        validator_cls.check_schema(schema)
        validator = validator_cls(schema, registry=referencing.Registry())
        errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    except JsonSchemaError as exc:
        raise SchemaResolutionError(
            f"resource at {schema_url!r} is not a valid JSON Schema: {exc.message}"
        ) from exc
    except JsonValidationError as exc:
        raise SchemaValidationError(
            f"could not validate against schema {schema_url!r}: {exc.message}") from exc
    except Unresolvable as exc:
        # a remote $ref (fetching is off) or a broken local $ref — fail closed.
        raise SchemaResolutionError(
            f"schema {schema_url!r} has an unresolvable $ref "
            f"(remote $ref resolution is off): {exc}") from exc
    except RecursionError as exc:
        raise SchemaResolutionError(
            f"schema {schema_url!r} is too deeply nested to validate") from exc
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "<root>"
        raise SchemaValidationError(
            f"credential does not conform to schema {schema_url!r}: "
            f"at {where}: {first.message}")


def validate_credential_schema(
    credential: dict[str, Any], *,
    resolve_credential_schema: ResolveCredentialSchema,
) -> SchemaValidationResult:
    """Validate *credential* against every ``JsonSchema`` it declares.

    Fetches each declared schema via *resolve_credential_schema* and validates the
    whole credential document against it. Raises :class:`SchemaValidationError` on
    a mismatch, :class:`SchemaResolutionError` if a schema cannot be fetched or is
    not a valid JSON Schema, and :class:`UnsupportedSchemaType` for a schema type
    this verifier cannot check (e.g. ``JsonSchemaCredential``). Returns a
    :class:`SchemaValidationResult` recording which schema URLs were applied (which
    may be empty if the credential declares no ``credentialSchema``)."""
    from .did.base import DidError  # the injected fetch's own transport/SSRF errors

    applied: list[str] = []
    for ref in parse_credential_schemas(credential):
        if ref.type != SCHEMA_TYPE_JSON:
            raise UnsupportedSchemaType(
                f"credentialSchema type {ref.type!r} is not supported "
                f"(only {SCHEMA_TYPE_JSON!r} is validated)")
        try:
            raw = resolve_credential_schema(ref.id)
        except (SchemaError, DidError) as exc:
            raise SchemaResolutionError(
                f"could not resolve schema {ref.id!r}: {exc}") from exc
        if not isinstance(raw, (bytes, bytearray)):
            raise SchemaResolutionError(
                f"schema {ref.id!r} resolver must return bytes, got {type(raw).__name__}")
        if ref.digest_sri:                        # integrity pin — verify BEFORE parsing
            _verify_sri(bytes(raw), ref.digest_sri, ref.id)
        try:
            resource = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            raise SchemaResolutionError(f"schema {ref.id!r} is not valid JSON: {exc}") from exc
        if not isinstance(resource, dict):
            raise SchemaResolutionError(
                f"schema {ref.id!r} did not resolve to a JSON object")
        _validate_instance(credential, _extract_json_schema(resource), ref.id)
        applied.append(ref.id)

    return SchemaValidationResult(validated=bool(applied), schemas=tuple(applied))


_SRI_HASHES = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}


def _verify_sri(data: bytes, integrity: str, url: str) -> None:
    """Verify a Subresource-Integrity metadata string against *data*, failing closed.

    ``integrity`` is one or more space-separated ``<alg>-<base64(digest)>`` options
    (W3C SRI); *data* matches if it satisfies ANY option of the strongest algorithm
    present. Comparison is constant-time. Raises :class:`SchemaResolutionError` on an
    unparseable string or a mismatch."""
    options: list[tuple[str, bytes]] = []
    for token in integrity.split():
        alg, _, b64 = token.partition("-")
        if alg in _SRI_HASHES and b64:
            try:
                options.append((alg, base64.b64decode(b64)))
            except (ValueError, TypeError):
                continue
    if not options:
        raise SchemaResolutionError(
            f"schema {url!r} has an unparseable digestSRI {integrity!r}")
    strongest = max(alg for alg, _ in options)                 # sha512 > sha384 > sha256
    for alg, expected in options:
        if alg != strongest:
            continue
        if hmac.compare_digest(_SRI_HASHES[alg](data).digest(), expected):
            return
    raise SchemaResolutionError(
        f"schema {url!r} does not match its digestSRI ({strongest})")


__all__ = [
    "CredentialSchemaRef",
    "ResolveCredentialSchema",
    "SCHEMA_TYPE_JSON",
    "SCHEMA_TYPE_JSON_CREDENTIAL",
    "SchemaBackendUnavailable",
    "SchemaError",
    "SchemaResolutionError",
    "SchemaUnavailable",
    "SchemaValidationError",
    "SchemaValidationResult",
    "UnsupportedSchemaType",
    "parse_credential_schemas",
    "validate_credential_schema",
]
