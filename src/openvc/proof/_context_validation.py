"""
openvc.proof._context_validation — JSON-LD context validation for the RDF-canonicalized
Data Integrity suites (``eddsa-rdfc-2022``, ``ecdsa-rdfc-2019``, ``ecdsa-sd-2023``).

Those suites sign the **RDF dataset** a document expands to, not its JSON. Every policy
check after the signature — the validity window, ``credentialStatus``,
``credentialSchema``, ``type``, the issuer and subject the result reports — reads the
**JSON**. The two only agree when the JSON spells the dataset the way the verifier's
trusted contexts would, so Data Integrity §2.4.1 requires context validation (§4.6, "or
one that achieves equivalent protections") after the proof verifies. Without it, a
document can keep its signed dataset while showing different JSON:

* a signed member re-keyed to its absolute IRI (or a compact IRI, a keyword spelling, an
  ``@value`` object) disappears from the key the policy reads;
* an inline ``@context`` can alias a signed term, null out a term, or replace the VC
  context outright and re-map ``credentialSubject``;
* a term no trusted context defines is dropped from the dataset, so its JSON value is
  never signed at all;
* ``@included`` / ``@reverse`` / a top-level ``@graph`` / a nested re-description of the
  document node can move signed statements out of the object the policy reads;
* a statement whose subject, predicate or object is not an IRI the RDF conversion keeps
  (an ``@id`` with whitespace, a blank-node predicate from ``"@vocab": "_:"``, ...) is
  silently dropped from the dataset — a whole forged top-level node can ride on that.

:func:`validate_document` closes all of them with one invariant: the document (and its
proof) must be the **compacted form** of its own expansion under a context the verifier
trusts — the VC base context first, then only URLs the offline loader serves (bundled or
caller-injected ``extra_contexts``) or inline objects that carry nothing but ``@vocab``
with an absolute IRI (which can neither alias, re-map nor drop a term: a defined term
always wins over ``@vocab`` in compaction), and the expansion must carry no statement the
RDF conversion would drop (JSON-LD "safe mode"). The comparison tolerates exactly the
two spellings JSON-LD treats as identical — a one-element array vs its element, and a
node reference ``{"id": X}`` vs ``X`` — and nothing else, compared as canonical JSON so
``true``/``1`` and ``1``/``1.0`` stay distinct.

The suites run it on the signing side as well, so openvc never issues a credential whose
JSON carries statements its signature does not cover.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .errors import ProofError, ProofMalformed

VC_BASE_CONTEXTS = frozenset({
    "https://www.w3.org/ns/credentials/v2",     # VCDM 2.0 §4.3
    "https://www.w3.org/2018/credentials/v1",   # VCDM 1.1 §4.1
})

# Expanded-form keywords refused outright. @included / @reverse let a statement about a
# node live outside that node's own JSON object; @index / @direction annotate JSON the
# RDF dataset does not carry (openvc canonicalizes without rdfDirection), so their values
# would be unsigned. None is produced by issuing a plain credential.
_REFUSED_KEYWORDS = ("@included", "@reverse", "@index", "@direction")

# pyld's own absolute-IRI test (pyld 2.0.4 and 3.x alike): toRDF drops a statement whose
# subject, predicate or IRI object fails it, and drops blank-node ("_:") predicates.
_RDF_IRI = re.compile(r"^([A-Za-z][A-Za-z0-9+-.]*|_):[^\s]*$")

# Embedded credentials inside a presentation carry their own @context and proof and are
# verified one by one with their own validation; the presentation's check skips them.
_EMBEDDED_CREDENTIALS = "verifiableCredential"


def validate_document(
    unsecured: dict[str, Any], proof_config: dict[str, Any], loader: Any,
) -> None:
    """Require *unsecured* (the document without ``proof``) and *proof_config* (the proof
    without ``proofValue``, carrying the document ``@context``) to be in the canonical
    compacted form described in the module docstring, else raise
    :class:`~openvc.proof.errors.ProofMalformed`. *loader* is the suite's offline
    document loader — the same one canonicalization used."""
    _check_context(unsecured.get("@context"))
    document = unsecured
    if _is_presentation(unsecured):
        document = {k: v for k, v in unsecured.items() if k != _EMBEDDED_CREDENTIALS}
    _check_compacted(document, loader, what="document")
    _check_compacted(proof_config, loader, what="proof")


def _check_context(context: Any) -> None:
    entries = [context] if isinstance(context, str) else context
    if not isinstance(entries, list) or not entries:
        raise ProofMalformed("@context must be a URL or a non-empty array")
    if not isinstance(entries[0], str) or entries[0] not in VC_BASE_CONTEXTS:
        raise ProofMalformed(
            f"the first @context entry must be the VC base context "
            f"({' or '.join(sorted(VC_BASE_CONTEXTS))})")
    for entry in entries[1:]:
        if isinstance(entry, str) and entry:
            continue                     # resolved only by the offline loader
        if isinstance(entry, dict) and set(entry) == {"@vocab"}:
            if _is_predicate(entry["@vocab"]):
                continue
            raise ProofMalformed("an inline @vocab must be an absolute IRI")
        raise ProofMalformed(
            "an inline @context object may only carry @vocab; publish other term "
            "definitions as a context URL and pass it via extra_contexts")


def _is_presentation(document: dict[str, Any]) -> bool:
    types = document.get("type")
    types = [types] if isinstance(types, str) else types
    return isinstance(types, list) and "VerifiablePresentation" in types


def _check_compacted(document: dict[str, Any], loader: Any, *, what: str) -> None:
    from pyld import jsonld          # the caller already canonicalized with pyld

    options = {"documentLoader": loader}
    try:
        expanded = jsonld.expand(document, options)
        if not (isinstance(expanded, list) and len(expanded) == 1
                and isinstance(expanded[0], dict)):
            raise ProofMalformed(f"the {what} must describe exactly one top-level node")
        node = expanded[0]
        _check_expanded(node, node.get("@id"), what=what, top=True)
        compacted = jsonld.compact(expanded, document["@context"], options)
        same = _canonical(compacted) == _canonical(document)
        where = "" if same else _first_difference(
            _normalize(document), _normalize(compacted), "")[:200]
    except ProofError:
        raise
    except Exception as exc:         # pyld's JsonLdError, a non-JSON value, ...
        raise ProofMalformed(f"cannot validate the {what}'s JSON-LD form: {exc}") from exc
    if not same:
        raise ProofMalformed(
            f"the {what} is not in compacted form under its @context (at {where or '/'}): "
            f"a member spelled as an IRI or keyword, a relative IRI, or a term no "
            f"trusted context defines — whose value the signature does not cover")


def _is_predicate(value: Any) -> bool:
    return isinstance(value, str) and not value.startswith("_:") and bool(
        _RDF_IRI.match(value))


def _is_node_iri(value: Any) -> bool:
    return isinstance(value, str) and bool(_RDF_IRI.match(value))


def _check_expanded(value: Any, top_id: Any, *, what: str, top: bool = False) -> None:
    """Walk the expanded form: refuse the keywords that detach statements from their
    node, a nested re-description of the document node, and anything the RDF conversion
    would silently drop — so the dataset holds exactly what the JSON says."""
    if isinstance(value, list):
        for item in value:
            _check_expanded(item, top_id, what=what)
        return
    if not isinstance(value, dict):
        return
    for keyword in _REFUSED_KEYWORDS:
        if keyword in value:
            raise ProofMalformed(f"the {what} uses {keyword}, which is not accepted")
    if "@value" in value:
        return                   # a literal (even an @json one) is data, not graph
    if "@id" in value and not _is_node_iri(value["@id"]):
        raise ProofMalformed(
            f"the {what} has a node id the signed dataset drops: {_brief(value['@id'])}")
    for rdf_type in value.get("@type", ()):
        if not _is_node_iri(rdf_type):
            raise ProofMalformed(
                f"the {what} has a type the signed dataset drops: {_brief(rdf_type)}")
    if (not top and isinstance(top_id, str) and value.get("@id") == top_id
            and set(value) - {"@id"}):
        raise ProofMalformed(
            f"the {what}'s own node {_brief(top_id)} is described again inside the {what}")
    for key, item in value.items():
        if not key.startswith("@") and not _is_predicate(key):
            raise ProofMalformed(
                f"the {what} has a property the signed dataset drops: {_brief(key)}")
        if key not in ("@id", "@type"):
            _check_expanded(item, top_id, what=what)


def _brief(value: Any) -> str:
    return repr(value)[:100] if isinstance(value, str) else type(value).__name__


def _normalize(value: Any) -> Any:
    """Fold the two spellings JSON-LD compaction treats as one: ``[x]`` -> ``x`` and the
    node reference ``{"id": X}`` -> ``X`` (``id`` is the protected ``@id`` alias of both
    VC base contexts)."""
    if isinstance(value, list):
        items = [_normalize(v) for v in value]
        return items[0] if len(items) == 1 else items
    if isinstance(value, dict):
        if set(value) == {"id"}:
            return _normalize(value["id"])
        return {k: _normalize(v) for k, v in value.items()}
    return value


def _first_difference(ours: Any, theirs: Any, path: str) -> str:
    """The JSON-pointer-ish path of the first place two normalized values differ —
    only to make the error actionable."""
    if isinstance(ours, dict) and isinstance(theirs, dict):
        for key in sorted(set(ours) | set(theirs)):
            if key not in ours or key not in theirs or (
                    _canonical(ours[key]) != _canonical(theirs[key])):
                if key in ours and key in theirs:
                    return _first_difference(ours[key], theirs[key], f"{path}/{key}")
                return f"{path}/{key}"
    if (isinstance(ours, list) and isinstance(theirs, list)
            and len(ours) == len(theirs)):
        for index, (a, b) in enumerate(zip(ours, theirs)):
            if _canonical(a) != _canonical(b):
                return _first_difference(a, b, f"{path}/{index}")
    return path


def _canonical(value: Any) -> str:
    return json.dumps(_normalize(value), sort_keys=True, ensure_ascii=False,
                      allow_nan=False)


__all__ = ["VC_BASE_CONTEXTS", "validate_document"]
