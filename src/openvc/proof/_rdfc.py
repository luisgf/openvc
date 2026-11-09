"""
openvc.proof._rdfc — RDF dataset canonicalization with a work budget.

The three RDF-canonicalizing suites (``eddsa-rdfc-2022``, ``ecdsa-rdfc-2019``,
``ecdsa-sd-2023``) canonicalize the document **before** any signature check, and
eddsa-rdfc-2022 before key resolution too. RDFC-1.0 hashes blank nodes by their
neighbourhood; when several blank nodes have the same first-degree hash it falls
back to *Hash N-Degree Quads*, which tries every permutation of the tied nodes and
recurses. On a symmetric graph (a clique, a complete bipartite graph, a hypercube)
that is factorial: a 2.5 KB credential with 8 mutually linked blank nodes costs
~20 s, 9 nodes ~4 minutes. RDFC-1.0 §4.4 therefore recommends a limit on that
work; pyld's ``URDNA2015`` has none, and openvc bounded only nesting depth and
input length.

:class:`_BudgetedURDNA2015` is pyld's ``URDNA2015`` with three ceilings, each
raising :class:`CanonicalizationBudgetExceeded` (a :class:`ProofMalformed`) with a
message that names the ceiling and quotes no document text:

* ``MAX_BLANK_NODES``  — distinct blank nodes in the dataset, checked *before* any
  hashing;
* ``MAX_HNDQ_CALLS``   — calls of Hash N-Degree Quads, the recursion;
* ``MAX_PERMUTATIONS`` — permutations scheduled by those calls, counted when a call
  builds its tied-node groups (``k!`` for a group of ``k``), i.e. *before* they run.

The ceilings were set from a measurement of every RDF-canonicalizing fixture in the
repository (D8, issue #381): at most 5 blank nodes, **0** Hash N-Degree Quads calls
and 0 permutations, i.e. nothing real ever ties. The limits are therefore far above
any observed use and far below the cost of an attack. Output is byte-identical to
``jsonld.normalize(..., algorithm="URDNA2015", format="application/n-quads")``.
"""
from __future__ import annotations

import functools
import math
from typing import Any

from .contexts import pyld_options
from .errors import ProofMalformed

# Distinct blank nodes in one canonicalized dataset. Cost without ties is linear, so this
# one is generous (4x the 64 of the plan, 50x the largest fixture): it exists to cap the
# per-call size of the recursion and of the issuer copies, not to bound the factorial.
MAX_BLANK_NODES = 256
# Hash N-Degree Quads invocations (recursion included) for one dataset. The repository's
# fixtures need none; a clique of 7 needs ~10^5.
MAX_HNDQ_CALLS = 10_000
# Permutations scheduled across the whole dataset. 10_000 admits a tied group of 7
# (5040) but not two of them, nor one of 8 (40320).
MAX_PERMUTATIONS = 10_000


class CanonicalizationBudgetExceeded(ProofMalformed):
    """The document needs more RDF canonicalization work than the budget allows
    (a blank-node graph symmetric enough to force the factorial fallback of RDFC-1.0).
    Refused before any signature check; never a statement about the signature."""


def _exceeded(what: str, limit: int) -> CanonicalizationBudgetExceeded:
    return CanonicalizationBudgetExceeded(
        f"RDF canonicalization budget exceeded: {what} (limit {limit}); "
        "the document's blank-node graph is too large or too symmetric to canonicalize")


@functools.lru_cache(maxsize=1)
def _budgeted_class() -> Any:
    # Built on first use: the core imports without pyld, the subclass needs it.
    from pyld.jsonld import URDNA2015

    class _BudgetedURDNA2015(URDNA2015):
        def __init__(self) -> None:
            super().__init__()
            self._hndq_calls = 0
            self._permutations = 0

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
            return super().hash_n_degree_quads(id_, issuer)

        def create_hash_to_related(self, id_: str, issuer: Any) -> Any:
            groups = super().create_hash_to_related(id_, issuer)
            for related in groups.values():
                # A group of k tied nodes is permuted k! ways; bound k first so the
                # factorial itself is never computed for a huge one.
                k = len(related)
                if k > 1:
                    if k > 10:
                        raise _exceeded("permutations of tied blank nodes", MAX_PERMUTATIONS)
                    self._permutations += math.factorial(k)
                    if self._permutations > MAX_PERMUTATIONS:
                        raise _exceeded("permutations of tied blank nodes", MAX_PERMUTATIONS)
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
