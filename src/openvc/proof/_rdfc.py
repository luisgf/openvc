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

The budget is **per canonicalization**, not per credential or per presentation: a VP
carrying N credentials canonicalizes N+1 documents, each with its own budget.

The numbers come from a measurement of every RDF-canonicalizing fixture in the
repository (D8, issue #381): at most 5 blank nodes, **0** Hash N-Degree Quads calls and
0 permutations, i.e. nothing in the fixtures ties.
The unit is calibrated on the dearest step (an issuer copy, about 0.1 microsecond per
unit); every other step is cheaper per unit (at most about 0.11 microsecond measured), so the
ceiling is a few seconds of one core at most, not a fixed duration (see the wiki).
Output is byte-identical to ``jsonld.normalize(..., algorithm="URDNA2015", format="application/n-quads")``.
"""
from __future__ import annotations

import functools
import math
from collections import Counter
from typing import Any

from .contexts import pyld_options
from .errors import ProofMalformed

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


def _exceeded(what: str, limit: int) -> CanonicalizationBudgetExceeded:
    return CanonicalizationBudgetExceeded(
        f"RDF canonicalization budget exceeded: {what} (limit {limit}); "
        "the document's blank-node graph is too large or too symmetric to canonicalize")


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


def canonicalize_nquads(document: Any, loader: Any) -> str:
    """Canonical N-Quads of a JSON-LD *document*: a drop-in for
    ``jsonld.normalize(document, pyld_options(loader, algorithm="URDNA2015",
    format="application/n-quads"))``, bounded by the budget above.

    Raises :class:`CanonicalizationBudgetExceeded` over budget; whatever pyld raises
    for a document it cannot process is left to the caller, as with ``normalize``."""
    from pyld import jsonld

    dataset = jsonld.to_rdf(document, pyld_options(loader, produceGeneralizedRdf=False))
    return str(new_canonicalizer().main(dataset, {"format": "application/n-quads"}))
