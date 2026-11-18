"""
openvc.proof._rdfc — RDF dataset canonicalization with a work budget.

The three RDF-canonicalizing suites (``eddsa-rdfc-2022``, ``ecdsa-rdfc-2019``,
``ecdsa-sd-2023``) canonicalize the document **before** any signature check, and
eddsa-rdfc-2022 before key resolution too. RDFC-1.0 hashes blank nodes by their
neighbourhood; when several blank nodes have the same first-degree hash it falls
back to *Hash N-Degree Quads*, which tries every distinct permutation of the tied
nodes and recurses. On a symmetric graph (a clique, a complete bipartite graph, a
hypercube) that is factorial: a 2.5 KB credential with 8 mutually linked blank nodes
costs ~20 s, 9 nodes ~4 minutes. And each call walks every quad of its node, so a
tied node carrying thousands of literals multiplies the cost of every call. RDFC-1.0
§4.4 recommends a limit; pyld's ``URDNA2015`` has none, and openvc bounded only
nesting depth and (for fetched documents) input length.

:class:`_BudgetedURDNA2015` is pyld's ``URDNA2015`` with a **work** ceiling as the
primary bound and two coarse ones, each raising
:class:`CanonicalizationBudgetExceeded` (a :class:`ProofMalformed`) with a message
that names the ceiling and quotes no document text:

* ``MAX_CANONICALIZATION_WORK`` — units of work in the Hash N-Degree Quads phase: one
  unit per quad visited when a call builds its related-node groups, a fixed ``_CALL_COST``
  per call, ``_COPY_FIXED_COST`` plus one per entry for **every deep copy of the
  identifier issuer** (pyld makes one for each group of related nodes in each call,
  singleton groups included; :class:`_ChargingIssuer` charges each where it is made), and,
  for every group of tied nodes, an upper bound on the permutations pyld will iterate times
  what one copy costs. Permutations are counted *before* they run, so a factorial is refused
  without being computed;
* ``MAX_BLANK_NODES`` — distinct blank nodes, checked before any hashing (blank
  nodes whose first-degree hashes differ cost nothing in this phase, so this only
  sizes the issuer copies the work counter already charges for);
* ``MAX_HNDQ_CALLS`` — a ceiling on the recursion itself.

Before any of that, pyld's JSON-LD to RDF conversion has a cost of its own: its node-map
builder checks each new value of a (subject, property) against every value already there, so
N values under one property cost about N**2/2 comparisons (a 71 KB credential, 10 s), and
the RDF suites run it before the signature. :class:`_ConversionCounter` replays that merge on
the *expanded* document and counts the ``compare_values`` calls pyld will make, refusing above
``MAX_CONVERSION_COMPARISONS`` before ``to_rdf`` runs (issue #426). The count is **summed over
the whole document** (every slot of every subject of every graph), and it is exact only when
its (graph, subject, property) partition is pyld's own, which is why the rules that decide it
are mirrored rather than approximated. It bounds the node-map comparisons and nothing else:
JSON-LD *expansion* (before the count, #446) and pyld's later steps (on ecdsa-sd-2023 the
N-Quads parsing, #447) are not bounded by it, and expansion is not linear (an inline scoped
context costs time proportional to the nodes that use it times its size). A presentation
secured with an RDF suite is one converted document: its count is the sum over the
credentials it embeds.

The budget is **per canonicalization**, not per credential or per presentation: a VP
carrying N credentials canonicalizes N+1 documents, each with its own budget.

The numbers come from a measurement of every RDF-canonicalizing fixture in the
repository (D8, issue #381): at most 5 blank nodes, **0** Hash N-Degree Quads calls and
0 permutations, i.e. nothing in the fixtures ties.
The unit is calibrated on the dearest step (an issuer copy, about 0.1 microsecond per
unit); every other step is cheaper per unit (at most about 0.11 microsecond measured), so the
ceiling is a few seconds of one core at most, not a fixed duration (see the wiki).
Output is byte-identical to
``jsonld.normalize(..., algorithm="URDNA2015", format="application/n-quads")``.
"""
from __future__ import annotations

import functools
import json
import math
from collections import Counter
from typing import Any

from .contexts import pyld_options
from .errors import ProofMalformed

# Value comparisons (pyld ``compare_values`` calls) the JSON-LD to RDF conversion may make,
# counted before it runs (see :func:`_conversion_cost`). A comparison costs about 0.3
# microsecond, so the ceiling is a fraction of a second of one core; the repository's RDF
# fixtures need 2 at most (see the wiki).
MAX_CONVERSION_COMPARISONS = 1_000_000
# Distinct blank nodes in one canonicalized dataset. Without ties a blank node costs
# nothing in Hash N-Degree Quads; the cap sizes the issuer copies the work counter charges.
MAX_BLANK_NODES = 1024
# Work units (see the module docstring) one canonicalization may spend in Hash N-Degree
# Quads. A unit is about 0.1 microsecond of the dearest step (an issuer copy); every other
# step measured is cheaper per unit (at most about 0.11 microsecond), so the ceiling is a few
# seconds of one core at most.
MAX_CANONICALIZATION_WORK = 20_000_000
# Hash N-Degree Quads invocations (recursion included): a coarse backstop; the work counter
# charges every call, so it binds first.
MAX_HNDQ_CALLS = 1_000_000
# What one Hash N-Degree Quads call costs besides the quads it visits (measured: 30 to 60
# microseconds of Python overhead).
_CALL_COST = 200
# What one deep copy of the identifier issuer costs: a fixed part (measured about 2.2
# microseconds) plus one unit per entry (about 0.12 microsecond). pyld makes one for every
# group of related nodes in every call, singletons included, so the copies are charged where
# they are made (:class:`_ChargingIssuer`), not estimated.
_COPY_FIXED_COST = 25
_COPY_ENTRY_COST = 1
# A tied group with more than this many *distinct* members has more than 10! permutations,
# above the work ceiling whatever else it costs.
_MAX_DISTINCT_TIED = 10


class CanonicalizationBudgetExceeded(ProofMalformed):
    """The document needs more RDF canonicalization work than the budget allows
    (a blank-node graph symmetric enough to force the factorial fallback of RDFC-1.0, or
    a tied node too large to revisit).
    Refused before any signature check; never a statement about the signature."""


def _exceeded(what: str, limit: int, why: str = "the document's blank-node graph is too "
              "large or too symmetric") -> CanonicalizationBudgetExceeded:
    return CanonicalizationBudgetExceeded(
        f"RDF canonicalization budget exceeded: {what} (limit {limit}); {why} to canonicalize")


_KEYWORDS = frozenset((
    "@base", "@container", "@context", "@default", "@direction", "@embed", "@explicit",
    "@first", "@graph", "@id", "@import", "@included", "@index", "@json", "@language",
    "@list", "@nest", "@none", "@omitDefault", "@propagate", "@protected", "@preserve",
    "@requireAll", "@reverse", "@set", "@type", "@value", "@version", "@vocab"))  # pyld's list


class _Slot:
    """The values pyld has stored under one (graph, subject, property): how many, and where
    the first one of each kind sits."""

    __slots__ = ("size", "first")

    def __init__(self) -> None:
        self.size = 0
        self.first: dict[Any, int] = {}


class _ConversionCounter:
    """A dry run of pyld's ``_create_node_map`` that only counts ``compare_values`` calls.

    Every ``add_value(..., allowDuplicate=False)`` pyld makes walks the values already stored
    under the same (graph, subject, property) until one compares equal; ``allowDuplicate=True``
    (``@list`` objects) costs nothing but still enlarges what later adds walk. The count is
    exact only if the **partition into (graph, subject, property) slots is the same as
    pyld's**, so every rule that decides it is mirrored, not approximated (a slot merged or
    split differently charges too little, because of the duplicate shortcut below):

    * subjects merge by ``@id``; blank-node labels, ``@type`` values and *forward* properties
      named ``_:x`` go through one ``IdentifierIssuer`` (replayed here, in pyld's order), a
      ``@reverse`` property is used as written; a node without ``@id`` gets a fresh label;
    * a node whose expanded ``@id`` is present but ``null`` (a keyword-like id such as
      ``"@a"``) is **one** subject, and the graph it names one graph; the references to it
      never compare equal (pyld 3.x) or always do (2.0.4), so they are charged as distinct;
    * a graph is named by its node's id, except ``@default`` (the default graph);
    * a value equals an earlier one only when it is identical (a relation finer than pyld's:
      NaN, ``@json`` and anything unusual are never equal), so a duplicate costs its position
      and a new value costs everything already stored."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.cost = 0
        self.slots: dict[tuple[Any, Any, str], _Slot] = {}
        self.fresh = 0
        self.issued: dict[str, str] = {}       # pyld's IdentifierIssuer('_:b'), replayed
        self.counter = 0

    def _issue(self, old: str | None) -> str:
        """``IdentifierIssuer.get_id``: the label of *old*, issued on first use."""
        if old is not None and old in self.issued:
            return self.issued[old]
        label = f"_:b{self.counter}"
        self.counter += 1
        if old is not None:
            self.issued[old] = label
        return label

    def _add(self, graph: Any, node: Any, prop: str, key: Any, allow_duplicate: bool) -> None:
        slot = self.slots.get((graph, node, prop))
        if slot is None:
            slot = self.slots[(graph, node, prop)] = _Slot()
        if allow_duplicate:
            slot.size += 1
            return
        found = slot.first.get(key)
        if found is not None:
            self.cost += found + 1
        else:
            self.cost += slot.size
            slot.first[key] = slot.size
            slot.size += 1
        if self.cost > self.limit:
            raise _exceeded("JSON-LD to RDF conversion work (value comparisons, summed over "
                            "the whole document)", self.limit,
                            "too many values share a property of one subject")

    def _value_key(self, value: dict) -> Any:
        """A key that is equal for two values only when pyld's ``compare_values`` is sure to
        call them equal (it compares ``@value`` with ``==``, so NaN never matches itself and
        ``1 == 1.0``; a value without a safe key gets one nothing else shares)."""
        raw = value.get("@value")
        if type(raw) in (str, bool, int) or (type(raw) is float and math.isfinite(raw)):
            rest: str | None = ""
            if len(value) > 1:
                try:
                    rest = json.dumps({k: v for k, v in value.items() if k != "@value"},
                                      sort_keys=True)
                except (TypeError, ValueError):
                    rest = None
            if rest is not None:
                return ("v", type(raw), raw, rest)
        self.fresh += 1
        return ("u", self.fresh)

    def walk(self, item: Any, graph: Any, subject: Any, prop: Any, in_list: bool,
             reverse_of: Any = None) -> None:
        """Mirror of one ``_create_node_map`` call, in pyld's order. *subject* is the id of the
        node the item hangs from, ``None`` where pyld has no string subject (the top, under
        ``@graph`` and ``@included``, below a node whose ``@id`` is ``null``); *reverse_of* is
        the node a ``@reverse`` item points back at."""
        if isinstance(item, list):
            for element in item:
                self.walk(element, graph, subject, prop, in_list, reverse_of)
            return
        if not isinstance(item, dict):
            return
        if "@value" in item:
            kind = item.get("@type")
            if isinstance(kind, str) and kind.startswith("_:"):
                self._issue(kind)
            if subject is not None and not in_list and reverse_of is None:
                self._add(graph, subject, prop, self._value_key(item), False)
            return
        if "@list" in item:
            self.walk(item["@list"], graph, subject, prop, True, reverse_of)
            if subject is not None and not in_list and reverse_of is None:
                self._add(graph, subject, prop, None, True)
            return
        for kind in item.get("@type", ()):      # pyld labels blank-node types first
            if isinstance(kind, str) and kind.startswith("_:"):
                self._issue(kind)
        node: Any
        if "@id" not in item:
            self._issue(None)
            self.fresh += 1
            node = ("fresh", self.fresh)
        else:
            raw = item["@id"]
            if raw is None:
                node = ("null",)                # every such node is the one subject ``None``
            else:
                node = ("id", str(raw))         # an IRI or a blank node label, same string
                if str(raw).startswith("_:"):
                    self._issue(str(raw))

        def reference(target: Any) -> Any:
            if target == ("null",):             # never (3.x) or always (2.0.4) equal: distinct
                self.fresh += 1
                return ("@id", ("nullref", self.fresh))
            return ("@id", target)

        if reverse_of is not None:
            self._add(graph, node, prop, reference(reverse_of), False)
        elif prop is not None and subject is not None and not in_list:
            self._add(graph, subject, prop, reference(node), False)
        below = None if node == ("null",) else node      # pyld: no string subject for ``None``
        for name, objects in sorted(item.items()):
            if name == "@id":
                continue
            if name == "@reverse":
                for reverse_property, items in objects.items():
                    self.walk(items, graph, None, reverse_property, False, node)
                continue
            if name == "@graph":
                # the graph a node names is its id, except ``@default`` (``@merged``, which pyld
                # also special-cases, is not a keyword: expansion turns it into a null ``@id``)
                named: Any = "@default" if node == ("id", "@default") else node
                self.walk(objects, named, None, None, False)
                continue
            if name == "@included":
                self.walk(objects, graph, None, None, False)
                continue
            if name in _KEYWORDS:
                if name != "@type":
                    continue
                for element in objects:
                    self._add(graph, node, "@type", ("t", element), False)
                continue
            slot_name = self._issue(name) if name.startswith("_:") else name
            for element in objects:
                self.walk(element, graph, below, slot_name, False)


def _conversion_cost(expanded: Any, limit: int) -> int:
    """The ``compare_values`` calls pyld's JSON-LD to RDF conversion will make for the
    *expanded* document, or a refusal (:class:`CanonicalizationBudgetExceeded`) as soon as the
    count passes *limit*. Linear in the size of the expanded document."""
    counter = _ConversionCounter(limit)
    counter.walk(expanded, "@default", None, None, False)
    return counter.cost


def _distinct_permutations(related: list[str], cap: int) -> int:
    """An upper bound on the permutations pyld iterates for the related-node list *related*,
    or a value above *cap* when there are more (or when counting them exactly would itself
    be costly).

    The list is a multiset (a graph name is related once per quad it names, with no
    predicate), and pyld's ``permutations`` yields only the *distinct* ones, so the bound is
    ``k! / prod(m! for each repeated member)``; a set-based count would under-count. (pyld's
    duplicate-aware generator yields far fewer than that for a mixed multiset, so a contrived
    document is refused that pyld would canonicalize.)"""
    counts = Counter(related)
    if len(counts) > _MAX_DISTINCT_TIED:
        return cap + 1
    total = 1
    placed = 0
    for multiplicity in counts.values():
        placed += multiplicity
        if placed > 200 and min(multiplicity, placed - multiplicity) > 20:
            return cap + 1                 # C(200, 20) is above any cap; do not compute it
        total *= math.comb(placed, multiplicity)
        if total > cap:
            return cap + 1
    return total


@functools.lru_cache(maxsize=1)
def _budgeted_class() -> Any:
    # Built on first use: the core imports without pyld, the subclass needs it.
    # Both live in pyld.jsonld in 2.0.4 and are imported there in 3.x
    from pyld.jsonld import URDNA2015, IdentifierIssuer

    class _ChargingIssuer(IdentifierIssuer):
        """An identifier issuer whose every deep copy is charged to the budget of the
        canonicalizer that owns it. pyld copies the issuer for each group of related nodes in
        each Hash N-Degree Quads call (singleton groups too), and each copy is linear in the
        number of issued identifiers."""

        _canon: Any = None

        def __deepcopy__(self, memo: Any) -> Any:
            self._canon._charge(_COPY_FIXED_COST + _COPY_ENTRY_COST * len(self.existing))
            new = self.__class__.__new__(self.__class__)
            for key, value in self.__dict__.items():
                new.__dict__[key] = (
                    dict(value) if isinstance(value, dict)
                    else list(value) if isinstance(value, list) else value)
            return new

    class _BudgetedURDNA2015(URDNA2015):
        def __init__(self) -> None:
            super().__init__()
            self._hndq_calls = 0
            self._work = 0

        def _charge(self, units: int) -> None:
            self._work += units
            if self._work > MAX_CANONICALIZATION_WORK:
                raise _exceeded("canonicalization work (Hash N-Degree Quads)",
                                MAX_CANONICALIZATION_WORK)

        def main(self, dataset: Any, options: Any) -> Any:
            # Before hashing and before pyld mutates the quads: count distinct blank
            # nodes the way pyld's own step 2 does (subject, object, graph name; never
            # the predicate).
            seen: set[str] = set()
            for graph_name, triples in dataset.items():
                if isinstance(graph_name, str) and graph_name.startswith("_:"):
                    seen.add(graph_name)
                for quad in triples:
                    for key, component in quad.items():
                        if key != "predicate" and component["type"] == "blank node":
                            seen.add(component["value"])
                if len(seen) > MAX_BLANK_NODES:
                    raise _exceeded(f"more than {MAX_BLANK_NODES} blank nodes", MAX_BLANK_NODES)
            return super().main(dataset, options)

        def hash_n_degree_quads(self, id_: str, issuer: Any) -> Any:
            self._hndq_calls += 1
            if self._hndq_calls > MAX_HNDQ_CALLS:
                raise _exceeded("Hash N-Degree Quads calls", MAX_HNDQ_CALLS)
            self._charge(_CALL_COST)
            if not isinstance(issuer, _ChargingIssuer):
                issuer.__class__ = _ChargingIssuer       # the first issuer comes from pyld's main
                issuer._canon = self
            return super().hash_n_degree_quads(id_, issuer)

        def create_hash_to_related(self, id_: str, issuer: Any) -> Any:
            # The walk below visits every quad of the node, literals included: charge it
            # first, so a fat node is refused before it is walked.
            self._charge(len(self.blank_node_info[id_]["quads"]))
            groups = super().create_hash_to_related(id_, issuer)
            copy_cost = _COPY_FIXED_COST + _COPY_ENTRY_COST * len(issuer.existing)
            for related in groups.values():
                if len(related) > 1:
                    # An upper bound on what pyld iterates, counted before it does so a
                    # factorial is never run (each copy is charged again when it is made).
                    cap = MAX_CANONICALIZATION_WORK - self._work
                    permutations = _distinct_permutations(related, cap)
                    self._charge(permutations * (len(related) + copy_cost))
            return groups

    return _BudgetedURDNA2015


def new_canonicalizer() -> Any:
    """A fresh budgeted pyld ``URDNA2015`` (one per dataset: it carries the counters).
    ``.main(dataset, options)`` canonicalizes an RDF dataset; ``.canonical_issuer``
    holds the ``{input label: _:c14nN}`` map afterwards."""
    return _budgeted_class()()


def to_rdf(document: Any, loader: Any, **options: Any) -> Any:
    """pyld's ``jsonld.to_rdf`` of a JSON-LD *document*, refused first if the comparisons its
    node-map merge will make (see :func:`_conversion_cost`) are over
    ``MAX_CONVERSION_COMPARISONS``. *options* are the ``to_rdf`` options (the loader's resolver
    is added); the conversion itself is pyld's, on the document as written.

    The document is therefore expanded twice (once to count, once inside ``to_rdf``). Handing
    ``to_rdf`` the expanded form would save that, but on pyld 3.x a second expansion is not the
    identity: it resolves a relative ``@id`` that a ``"@base": null`` context kept relative
    against the default base, which changes the signed dataset (the forged-type document of
    ``test_dcql_type_values.py``). Expansion is pyld's and is not bounded here: an inline
    scoped context costs it time proportional to the nodes that use it times its size.

    Raises :class:`CanonicalizationBudgetExceeded` over budget, before the conversion runs;
    whatever pyld raises for a document it cannot process is left to the caller."""
    from pyld import jsonld

    try:
        expanded = jsonld.expand(document, pyld_options(loader))
    except jsonld.JsonLdError:
        pass                          # to_rdf expands again and raises the error callers expect
    else:
        _conversion_cost(expanded, MAX_CONVERSION_COMPARISONS)
    return jsonld.to_rdf(document, pyld_options(loader, **options))


def canonicalize_nquads(document: Any, loader: Any) -> str:
    """Canonical N-Quads of a JSON-LD *document*: a drop-in for
    ``jsonld.normalize(document, pyld_options(loader, algorithm="URDNA2015",
    format="application/n-quads"))``, bounded by the budget above.

    Raises :class:`CanonicalizationBudgetExceeded` over budget; whatever pyld raises
    for a document it cannot process is left to the caller, as with ``normalize``."""
    dataset = to_rdf(document, loader, produceGeneralizedRdf=False)
    return str(new_canonicalizer().main(dataset, {"format": "application/n-quads"}))
