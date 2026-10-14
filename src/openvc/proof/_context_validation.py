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
  silently dropped from the dataset — a whole forged top-level node can ride on that;
* an array nested directly in an array is flattened by expansion (outside ``@list``), so
  ``credentialStatus: [S1, [S2]]`` signs as ``[S1, S2]`` and ``[[S]]`` as ``S``, while
  every JSON reader that expects objects skips the inner array.

:func:`validate_document` closes all of them with one invariant: the document (and its
proof) must be the **compacted form** of its own expansion under a context the verifier
trusts — the VC base context first, then only URLs the offline loader serves (bundled or
caller-injected ``extra_contexts``) or inline objects that carry nothing but ``@vocab``
with an absolute IRI (which can neither alias, re-map nor drop a term while the context
defining it is listed: a defined term always wins over ``@vocab`` in compaction; what
stops a holder dropping that context and spelling its IRIs through the ``@vocab`` is the
second rule below), and the expansion must carry no statement the RDF conversion would
drop (JSON-LD "safe mode"). The comparison tolerates exactly the two spellings JSON-LD
treats as identical — a one-element array vs its element (as a property value, never an
array inside an array: compaction only emits that for a ``@list`` of lists, and then
both sides carry it), and a node reference ``{"id": X}`` vs ``X`` — and nothing else,
compared as canonical JSON so ``true``/``1`` and ``1``/``1.0`` stay distinct.

Being the compacted form is necessary but not sufficient. Compaction only folds a
statement into a term when the value matches the term's definition; otherwise it keeps
the predicate's absolute IRI (or a compact IRI, or a suffix of an ``@vocab``) as the key,
and that spelling *is* the compacted form. So a ``validUntil`` / ``validFrom`` or a proof
``expires`` written as an untyped (or language-tagged) string under its IRI, or a
``credentialStatus`` given as a literal, signs that value, survives the comparison
unchanged, and is invisible to the policy reading the term: an issuer-signed expired
credential verified as never expiring. Hence the second rule: in the compacted form, a
key — or a ``type`` value, which is vocabulary-relative in the same way — that stands
for an IRI some trusted context defines a term for (at the top level or in a scoped
context) must be one of those terms, and when the VC base context itself defines a term
for that IRI, one of the *base context's* terms. "Trusted" means every context the
verifier's loader serves, bundled or injected, whether or not the document lists it:
the document's ``@context`` is the holder's to edit, so a holder who drops an injected
status-list context (or moves a v2 credential onto a VC 1.1 base the verifier also
serves) and adds an inline ``@vocab`` keeps the dataset, the signature and the
compacted round trip, and would otherwise spell a status entry's type and members out
of the status check's sight. The base-context rule refuses an alias an injected context
gives a core IRI (``"until": ".../credentials#validUntil"``, uncoerced, or coerced like
the core term but shorter so compaction prefers it): the policy reads only the core
term. The rule is a superset on purpose: it does not track which contexts are in play
or where a scoped term is in effect, so an IRI some served context defines anywhere
(``created``, ``nonce`` and ``challenge`` are terms only inside the base context's
``DataIntegrityProof`` scope) is refused under any other spelling everywhere, even at a
node where no term for it is active and that spelling is what compaction emits. An IRI
no served context defines a term for is left alone. A term defined without ``@id`` is
indexed under the ``@vocab`` values the served contexts set and those the document's
own inline ``@vocab`` objects give it — never one per inline object, so the index does
not grow with the document.

Third, a ``credentialStatus`` entry is described where the status check reads it: a node
under the top-level ``credentialStatus`` whose ``@id`` is also described anywhere else
in the document — a nested node's ``credentialStatus`` included, which the status check
never reads — is refused. RDF lets a node referenced from two properties be described
under either, so an issuer's entry also named by another property could otherwise be
moved there and left under ``credentialStatus`` as ``{"id": X}`` or with only an
unrelated type, its revocation bit never read.

The suites run it on the signing side as well, so openvc never issues a credential whose
JSON carries statements its signature does not cover.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .contexts import DocumentLoaderError
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

# The predicate of `credentialStatus` in both VC base contexts.
_CREDENTIAL_STATUS = "https://www.w3.org/2018/credentials#credentialStatus"

# Bound on the walk of a document's trusted contexts (a context URL that imports another,
# scoped contexts inside scoped contexts, a term defined by another term). Real contexts
# stop at two or three levels.
_MAX_CONTEXT_DEPTH = 16


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
    indexes: dict[str, _TermIndex] = {}      # the proof shares the document's @context
    _check_compacted(document, loader, what="document", indexes=indexes)
    _check_compacted(proof_config, loader, what="proof", indexes=indexes)


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


def _check_compacted(document: dict[str, Any], loader: Any, *, what: str,
                     indexes: dict[str, _TermIndex]) -> None:
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
        misspelled = None
        if same:
            # The content of an @json literal compacts to raw JSON whose keys are data,
            # not properties: stub it out first (rare, so a second compaction only then).
            stubbed = _stub_json_literals(expanded)
            if stubbed is not expanded:
                compacted = jsonld.compact(stubbed, document["@context"], options)
            context_key = _canonical(document["@context"])
            if context_key not in indexes:
                indexes[context_key] = _term_index(document["@context"], loader)
            misspelled = _misspelled_key(compacted, "", indexes[context_key])
    except ProofError:
        raise
    except Exception as exc:         # pyld's JsonLdError, a non-JSON value, ...
        raise ProofMalformed(f"cannot validate the {what}'s JSON-LD form: {exc}") from exc
    if not same:
        raise ProofMalformed(
            f"the {what} is not in compacted form under its @context (at {where or '/'}): "
            f"a member spelled as an IRI or keyword, a relative IRI, an array nested in "
            f"an array, or a term no trusted context defines — whose value the signature "
            f"does not cover")
    if misspelled is not None:
        raise ProofMalformed(
            f"the {what} spells a property (or a type) a trusted context defines other "
            f"than by its term (at {misspelled[:200]}): its value does not match the "
            f"term's definition (an untyped date, a literal for a node, ...), the context "
            f"defining the term was left out of the @context, the term is an alias an "
            f"injected context gives a VC base context IRI, or the IRI is used where its "
            f"term is not in scope — the member the policy reads would not carry what was "
            f"signed")
    _check_status_in_place(node, what=what)


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


def _check_status_in_place(node: dict[str, Any], *, what: str) -> None:
    """Refuse a ``credentialStatus`` entry (expanded form) of the top-level node whose
    node is also described — given any member besides ``@id`` — anywhere else: the
    status check reads only what sits under the top-level ``credentialStatus``, and RDF
    lets the issuer's entry be described under any property that references it (see the
    module docstring), a ``credentialStatus`` of a nested node included."""
    in_status: set[str] = set()
    described: set[str] = set()
    _collect_status_nodes(node, False, in_status, described, top=True)
    moved = in_status & described
    if moved:
        raise ProofMalformed(
            f"the {what}'s credentialStatus entry {_brief(min(moved))} is described "
            f"outside credentialStatus, where the status check does not read it")


def _collect_status_nodes(value: Any, under_status: bool, in_status: set[str],
                          described: set[str], *, top: bool = False) -> None:
    """Add to *in_status* the ``@id`` of every node object directly under the *top*
    node's ``credentialStatus``, and to *described* the ``@id`` of every other node
    object that carries a member besides ``@id`` — one under a nested node's
    ``credentialStatus`` too, which the status check never reads."""
    if isinstance(value, list):
        for item in value:
            _collect_status_nodes(item, under_status, in_status, described)
        return
    if not isinstance(value, dict) or "@value" in value:
        return                          # a literal (even an @json one) is data
    if "@list" in value:
        _collect_status_nodes(value["@list"], under_status, in_status, described)
        return
    node_id = value.get("@id")
    if isinstance(node_id, str):
        if under_status:
            in_status.add(node_id)
        elif set(value) - {"@id"}:
            described.add(node_id)
    for key, item in value.items():
        if key not in ("@id", "@type"):
            _collect_status_nodes(item, top and key == _CREDENTIAL_STATUS, in_status,
                                  described)


def _brief(value: Any) -> str:
    return repr(value)[:100] if isinstance(value, str) else type(value).__name__


def _normalize(value: Any, *, element: bool = False) -> Any:
    """Fold the two spellings JSON-LD compaction treats as one: ``[x]`` -> ``x`` and the
    node reference ``{"id": X}`` -> ``X`` (``id`` is the protected ``@id`` alias of both
    VC base contexts).

    ``[x]`` folds only as a property value (not as an *element* of an array) and only
    when ``x`` is not itself an array: expansion flattens an array nested in an array
    (outside ``@list``), so ``[[S]]`` and ``[S1, [S2]]`` keep the dataset — and the
    signature — of ``S`` and ``[S1, S2]`` while every JSON reader that expects objects
    skips the inner array. Folding it away would hide exactly that difference; a
    ``@list`` of lists is emitted nested by compaction too, so it still compares equal."""
    if isinstance(value, list):
        items = [_normalize(v, element=True) for v in value]
        if len(items) == 1 and not element and not isinstance(value[0], list):
            return items[0]
        return items
    if isinstance(value, dict):
        if set(value) == {"id"}:
            return _normalize(value["id"], element=element)
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
            if isinstance(a, list) is not isinstance(b, list):
                return f"{path}/{index}"         # an array where the other has none
            if _canonical(a) != _canonical(b):
                return _first_difference(a, b, f"{path}/{index}")
    return path


def _canonical(value: Any) -> str:
    return json.dumps(_normalize(value), sort_keys=True, ensure_ascii=False,
                      allow_nan=False)


# --------------------------------------------------------------------------- #
# Term spelling of defined IRIs
# --------------------------------------------------------------------------- #

class _TermIndex:
    """What the verifier's trusted contexts define: *spellings* (IRI -> every term
    defined as it), *iris* (term -> every IRI it is defined as, which also resolves a
    compact IRI's prefix), the ``@vocab`` values in play, *suffixes* (a bare key -> the
    defined IRIs that some ``@vocab`` plus the key names), *type_keys* (``@type`` and the
    terms aliased to it), *base* (IRI -> the terms the VC base context alone defines as
    it) and *verdicts* (a memo of :func:`_is_misspelled` per spelling). A union over the
    top level and every scoped context of every served context, so a superset: the check
    built on it fails closed."""

    def __init__(self) -> None:
        self.spellings: dict[str, set[str]] = {}
        self.iris: dict[str, set[str]] = {}
        self.vocabs: set[str] = set()
        self.suffixes: dict[str, set[str]] = {}
        self.type_keys: set[str] = {"@type"}
        self.base: dict[str, set[str]] = {}
        self.verdicts: dict[str, bool] = {}


def _term_index(context: Any, loader: Any) -> _TermIndex:
    """Index the term definitions of every context *loader* serves — the bundled ones
    and the caller's ``extra_contexts``, whether or not the document lists them — with
    anything they import and every type- or property-scoped context in them, plus the
    inline ``@vocab`` values of *context* (the document's ``@context``) that can name an
    IRI; and, separately, those of its first entry (the VC base context) alone.

    Not only the contexts the document lists: that list is the holder's to edit. With a
    trusted context dropped and an inline ``@vocab`` spelling its IRIs instead, the
    dataset, the signature and the compacted round trip all stay the same, while the
    IRIs would leave an index built from the document's own ``@context`` — so a status
    entry's type and members could be respelled out of the status check's sight."""
    served = getattr(loader, "contexts", None)
    if not isinstance(served, Mapping):
        raise TypeError("context validation needs the loader from "
                        "openvc.proof.contexts.document_loader (it lists what it serves)")
    entries = context if isinstance(context, list) else [context]
    seen: set[str] = set()
    base_objects: list[dict[str, Any]] = []
    _gather_contexts(entries[:1], loader, base_objects, seen, 0)
    objects = list(base_objects)
    _gather_contexts(sorted(served), loader, objects, seen, 0)
    index = _index_definitions(objects, _inline_vocabs(entries))
    index.base = _index_definitions(base_objects, set()).spellings
    # A bare key may stand for @vocab + key. Index every defined IRI once by each suffix
    # that follows one of the vocabularies, so the check then costs one lookup per key.
    cuts = sorted({len(vocab) for vocab in index.vocabs if vocab})
    for iri in index.spellings:
        for cut in cuts:
            if cut >= len(iri):
                break
            if iri[:cut] in index.vocabs:
                index.suffixes.setdefault(iri[cut:], set()).add(iri)
    return index


def _inline_vocabs(entries: list[Any]) -> set[str]:
    """The document's inline ``@vocab`` values that can give a key or a term its IRI:
    the one in effect where each context URL is last listed (a term that context defines
    without ``@id`` takes it) and the last one (what bare keys, and scoped contexts
    applied later, see). Any other is replaced before it names anything, so a document
    piling up inline ``@vocab`` objects does not grow the index."""
    current: str | None = None
    at_url: dict[str, str | None] = {}
    for entry in entries:
        if isinstance(entry, dict):
            vocab = entry.get("@vocab")
            current = vocab if isinstance(vocab, str) else None
        elif isinstance(entry, str):
            at_url[entry] = current
    return {vocab for vocab in (*at_url.values(), current) if vocab is not None}


def _index_definitions(objects: list[dict[str, Any]], inline_vocabs: set[str]) -> _TermIndex:
    definitions: dict[str, list[Any]] = {}
    vocabs: set[str] = set(inline_vocabs)
    index = _TermIndex()
    for obj in objects:
        for term, definition in obj.items():
            if term == "@vocab" and isinstance(definition, str):
                vocabs.add(definition)
            elif term.startswith("@") or definition is None:
                continue                         # a keyword, or a term nulled out
            elif isinstance(definition, dict) and "@reverse" in definition:
                continue                         # names no forward property
            else:
                definitions.setdefault(term, []).append(definition)
                target = definition.get("@id") if isinstance(definition, dict) \
                    else definition
                if target == "@type":
                    index.type_keys.add(term)    # an alias of @type ("type")

    index.vocabs = {iri for vocab in vocabs
                    for iri in _resolve(vocab, definitions, vocabs, 0)}
    for term, entries in definitions.items():
        for definition in entries:
            target = definition.get("@id") if isinstance(definition, dict) else definition
            if target is None:                   # no @id: the term itself, or @vocab + it
                target = term
            if not isinstance(target, str):
                continue
            for iri in _resolve(target, definitions, index.vocabs, 0):
                index.iris.setdefault(term, set()).add(iri)
                index.spellings.setdefault(iri, set()).add(term)
    return index


def _gather_contexts(context: Any, loader: Any, objects: list[dict[str, Any]],
                     seen: set[str], depth: int) -> None:
    """Collect every context object reachable from *context* into *objects*: an inline
    object, a URL (once each, through *loader*), its ``@import``, and the scoped
    ``@context`` of each term definition."""
    if depth > _MAX_CONTEXT_DEPTH:
        raise ProofMalformed("the @context nests too deeply")
    for entry in context if isinstance(context, list) else [context]:
        if isinstance(entry, str):
            if entry in seen:
                continue
            seen.add(entry)
            try:
                loaded = loader(entry)
            except DocumentLoaderError:
                # Expansion already loaded every context the document uses, so a URL
                # the loader does not serve (a scoped context of a type the document
                # never names) defines no term in play here. Any other failure is not
                # that, and must not silently drop a context's terms from the index.
                continue
            document = loaded.get("document") if isinstance(loaded, dict) else None
            if isinstance(document, str):
                document = json.loads(document)
            if isinstance(document, dict):
                _gather_contexts(document.get("@context"), loader, objects, seen,
                                 depth + 1)
        elif isinstance(entry, dict):
            objects.append(entry)
            if isinstance(entry.get("@import"), str):
                _gather_contexts(entry["@import"], loader, objects, seen, depth + 1)
            for key, definition in entry.items():
                if (not key.startswith("@") and isinstance(definition, dict)
                        and definition.get("@context") is not None):
                    _gather_contexts(definition["@context"], loader, objects, seen,
                                     depth + 1)


def _resolve(target: str, definitions: dict[str, list[Any]], vocabs: set[str],
             depth: int) -> set[str]:
    """The absolute IRIs a term definition's ``@id`` (or a term with none) may name: an
    absolute IRI as is, a compact IRI over any term defined as a prefix, another term,
    or — for a bare name — each ``@vocab`` plus it. Keywords name no IRI."""
    if target.startswith("@") or depth > _MAX_CONTEXT_DEPTH:
        return set()
    prefix, colon, suffix = target.partition(":")
    if colon:
        resolved = {target} if suffix.startswith("//") or prefix not in definitions \
            else set()
        if not suffix.startswith("//"):
            for base in _term_targets(prefix, definitions, vocabs, depth):
                resolved.add(base + suffix)
        return resolved or {target}
    if target in definitions:
        return _term_targets(target, definitions, vocabs, depth)
    return {vocab + target for vocab in vocabs}


def _term_targets(term: str, definitions: dict[str, list[Any]], vocabs: set[str],
                  depth: int) -> set[str]:
    resolved: set[str] = set()
    for definition in definitions.get(term, ()):
        target = definition.get("@id") if isinstance(definition, dict) else definition
        if isinstance(target, str) and target != term:
            resolved |= _resolve(target, definitions, vocabs, depth + 1)
        elif target is None or target == term:
            if ":" in term:                      # a compact or absolute IRI as the term
                resolved |= _resolve(term, definitions, vocabs, depth + 1)
            else:
                resolved |= {vocab + term for vocab in vocabs}
    return resolved


def _stub_json_literals(value: Any) -> Any:
    """*value* (expanded form) with the content of every ``@json`` literal replaced by 0,
    or *value* itself when it holds none."""
    if isinstance(value, list):
        items = [_stub_json_literals(item) for item in value]
        changed = any(new is not old for new, old in zip(items, value))
        return items if changed else value
    if not isinstance(value, dict):
        return value
    if "@value" in value:
        return dict(value, **{"@value": 0}) if value.get("@type") == "@json" else value
    copied = {key: _stub_json_literals(item) for key, item in value.items()}
    changed = any(copied[key] is not value[key] for key in value)
    return copied if changed else value


def _misspelled_key(value: Any, path: str, index: _TermIndex) -> str | None:
    """Path of the first key — or ``type`` value — of the compacted form *value* that
    stands for an IRI a trusted context defines a term for without being one of those
    terms — or, for an IRI the VC base context defines a term for, without being one of
    the base context's terms — or None."""
    if isinstance(value, list):
        for position, item in enumerate(value):
            where = _misspelled_key(item, f"{path}/{position}", index)
            if where is not None:
                return where
        return None
    if not isinstance(value, dict) or "@value" in value:
        return None                      # a literal is data, not properties
    for key, item in value.items():
        if key == "@context":
            continue
        if not key.startswith("@") and _is_misspelled(key, index):
            return f"{path}/{key}"
        if key in index.type_keys:
            # A type is vocabulary-relative like a key, so the same spellings arise:
            # the status check, for one, skips an entry whose type it does not know.
            many = isinstance(item, list)
            for position, spelling in enumerate(item if many else [item]):
                if (isinstance(spelling, str) and not spelling.startswith("@")
                        and _is_misspelled(spelling, index)):
                    return f"{path}/{key}" + (f"/{position}" if many else "")
        where = _misspelled_key(item, f"{path}/{key}", index)
        if where is not None:
            return where
    return None


def _is_misspelled(spelling: str, index: _TermIndex) -> bool:
    """Whether *spelling* (a non-keyword key or type of the compacted form) may stand for
    an IRI some trusted context defines a term for without being one of those terms (the
    VC base context's own, when it has one). Memoized per spelling, so a key repeated
    across the document costs one lookup."""
    verdict = index.verdicts.get(spelling)
    if verdict is None:
        verdict = False
        for iri in _key_iris(spelling, index):
            terms = index.base.get(iri) or index.spellings.get(iri)
            if terms and spelling not in terms:
                verdict = True
                break
        index.verdicts[spelling] = verdict
    return verdict


def _key_iris(key: str, index: _TermIndex) -> list[str]:
    """The defined IRIs a non-keyword key (or type) of the compacted form may stand for
    (an IRI no context defines a term for is never refused, so the others are left out).
    With a colon: itself, or a compact IRI over a term. Without one: every IRI a term of
    that name is defined as, in any scope, and an ``@vocab`` plus it. A superset, so the
    check fails closed."""
    if ":" not in key:
        return [*index.iris.get(key, ()), *index.suffixes.get(key, ())]
    prefix, _, suffix = key.partition(":")
    iris = [key]
    if not suffix.startswith("//"):
        iris.extend(base + suffix for base in index.iris.get(prefix, ()))
    return iris


__all__ = ["VC_BASE_CONTEXTS", "validate_document"]
