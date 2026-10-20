"""
openvc_ebsi.environments — the names ``for_ebsi`` accepts, as data.

This module imports no HTTP library, so ``versioning.py`` (and anything else that only needs
to know the names) works without the ``ebsi`` extra. It holds one row per environment name:
the name, and the host the name is pinned to. The record is data, never a version ladder: the
API-version specifics stay behind the adapters in :mod:`openvc_ebsi.versioning`.

What each name means, as measured and documented in
``docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md`` (2026-10-16):

* ``legacy-pilot`` — ``api-pilot.ebsi.eu``, the legacy per-service lane (the v5 adapters). The
  only place the recorded fixtures and the weekly smoke test are valid. It is the default.
* ``pilot`` — the same host and the same lane as ``legacy-pilot``, **deprecated** since 1.37.0
  (the maintainer's decision of 2026-10-19, ADR-0009 open question 4): ``for_ebsi("pilot")``
  emits a ``DeprecationWarning`` naming ``legacy-pilot`` and seeds the same allow-list. EBSI
  has since used "pilot" for the Core API pilot too, which is a different ledger that this name
  does not reach; the name will change meaning at the next MAJOR release (2.0, #74). Only
  ``for_ebsi`` warns: reading this table, ``EBSI_HOSTS`` or ``EBSI_BASE`` cannot.
* ``conformance`` — ``api-conformance.ebsi.eu``. A single measurement on 2026-10-16 completed
  no TCP connection within 12 s, so it may be transient; the row is kept as it was, like the
  ``production`` row (the maintainer's decision of 2026-10-19, ADR-0009 open question 4: for
  both, documentation only, with no warning and no refusal).
* ``production`` — ``api.ebsi.eu``. The certificate that host presented did not cover its name
  when measured, and none of the Trusted Nodes List's node hosts is under ``ebsi.eu``, so a
  client built from it is not known to complete a request. The row is kept as it was; where
  reads go instead is on the wiki page "EBSI node trust" (``wiki/EBSI-Node-Trust.md``).

* ``preprod``, ``prod`` — **node-derived**: EBSI Core API v1, whose hosts are the nodes of a
  signed Trusted Nodes List, not a name. They have no fixed host (``fixed_host`` is ``None``),
  so they are not in ``EBSI_HOSTS`` / ``EBSI_BASE`` and ``for_ebsi`` refuses them with
  :class:`~openvc_ebsi.errors.NodeDerivedEnvironment`. A client for them is built with
  :func:`openvc_ebsi.nodes.verify_node_list` and :func:`openvc_ebsi.node_client.for_nodes`
  (``wiki/EBSI-Node-Trust.md``), which own the Core v1 adapter names (``didr`` / ``tir``): the
  row holds none, so there is no second copy of that fact here. These are the Trusted Nodes
  List's own spellings (``nodes._ENVIRONMENTS``). There is no node-derived ``pilot`` row: that
  name stays the deprecated alias of ``legacy-pilot`` until the next MAJOR release (2.0, #74).

Only a fixed host is expressible as a host. An environment whose hosts come from a verified
node list has no fixed host (``fixed_host`` is ``None``) and is not part of the projection that
:mod:`openvc_ebsi.http` exposes as ``EBSI_HOSTS`` / ``EBSI_BASE``.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

# The one place the legacy pilot host is spelled out: the two table rows that name it and the
# default ``base`` of ``DidEbsiResolver`` all read it from here.
LEGACY_PILOT_HOST = "api-pilot.ebsi.eu"
LEGACY_PILOT_BASE = f"https://{LEGACY_PILOT_HOST}"


@dataclass(frozen=True)
class EbsiEnvironment:
    """One environment name. ``fixed_host`` is the host name (no scheme, no port) the name is
    pinned to, or ``None`` for an environment whose hosts are not fixed."""

    name: str
    fixed_host: str | None

    @property
    def base(self) -> str | None:
        """``https://<fixed_host>``, or ``None`` when there is no fixed host."""
        return None if self.fixed_host is None else f"https://{self.fixed_host}"


# ``legacy-pilot`` is appended after the three names that existed before it, so iterating
# ``EBSI_HOSTS`` still yields those three first, in the order they always had; the two
# node-derived names come last and are filtered out of that projection.
ENVIRONMENTS: Mapping[str, EbsiEnvironment] = MappingProxyType({
    env.name: env for env in (
        EbsiEnvironment("pilot", LEGACY_PILOT_HOST),
        EbsiEnvironment("conformance", "api-conformance.ebsi.eu"),
        EbsiEnvironment("production", "api.ebsi.eu"),
        EbsiEnvironment("legacy-pilot", LEGACY_PILOT_HOST),
        EbsiEnvironment("preprod", None),
        EbsiEnvironment("prod", None),
    )
})


def fixed_hosts() -> dict[str, str]:
    """``{name: host}`` for every environment that has a fixed host: the projection that
    :mod:`openvc_ebsi.http` publishes as ``EBSI_HOSTS``."""
    return {
        name: env.fixed_host for name, env in ENVIRONMENTS.items() if env.fixed_host is not None
    }
