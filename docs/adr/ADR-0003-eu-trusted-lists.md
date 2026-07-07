# ADR-0003 — Consume EU Trusted Lists (LOTL → national TL) as a verifier trust anchor source

**Status:** Accepted
**Date:** 2026-07-07
**Context owner:** openvc.trustlist

**Phasing (both landed):** **PR 1** — the hardened parser, the fail-closed LOTL→TL
walk, selection (default: `granted` + qualified-CA service types), and fixtures, with
XML-signature verification as an **injected callback**. **PR 2** — the optional
`[trustlist]` extra shipping `openvc.trustlist.verify_xades_enveloped`, a
`signxml`-based XAdES `verify_signature` verifier, proven by a sign→verify round-trip
and a full `walk_lotl` over signed LOTL + national TL (a live-EU-LOTL recorded vector
remains a future hardening step — it needs network + out-of-band Commission certs). The
callback stays injected, so core remains `cryptography` + `pyjwt`.

## Context

`openvc.x5c` already validates a JOSE `x5c` chain to a set of **caller-provided**
`x509.Certificate` trust anchors and binds the leaf to the issuer. What it cannot
answer is *where those anchors come from*. Under eIDAS 2.0 / EUDI the answer is the
**European Trusted Lists**: the Commission publishes a signed **List of Trusted
Lists (LOTL)** that points at each Member State's **Trusted List (TL)**, and each
national TL enumerates its qualified trust-service providers and their X.509
certificates. HAIP's `x509_hash` roots are these same certificates. This issue
closes the gap between *"the `x5c` chain is internally valid"* and *"the chain
roots in an **EU-recognised** anchor for the right service type, granted right now."*

The friction is that TLs are **signed XML** (XAdES enveloped signatures, ETSI TS
119 612; TLv6 becomes mandatory 28 Apr 2026). Full XML-DSig / XAdES verification
is heavy (canonicalisation, `lxml`/`xmlsec` or `signxml`) and would blow the
project's `cryptography` + `pyjwt` dependency budget if it entered core. Yet the
signature is exactly what makes a TL trustworthy, so it cannot simply be skipped.
This ADR resolves that tension.

## Non-goals

- **Not a full eIDAS validation engine.** No qualified-signature validation, no
  service-status *history*, no policy OIDs, no `AdditionalServiceInformation`
  semantics beyond what selects an anchor. Output is *anchors*, not legal advice.
- **Not EBSI-coupled.** Lives in `openvc.trustlist` (core). The EBSI plugin's TIR
  trust is a different, unrelated trust source and stays in `openvc_ebsi`.
- **Not a writer.** Read/parse/verify only, like the rest of openvc.

## Decisions

### D1 — Output: X.509 anchors that feed the existing `x5c` path
`openvc.trustlist` turns a LOTL→TL hierarchy into a filtered set of
`TrustServiceAnchor` records — each wrapping an `x509.Certificate` plus its
service metadata (TSP name, `ServiceTypeIdentifier`, `ServiceStatus`, scheme
territory, the SHA-256 of the DER for HAIP `x509_hash`). A helper returns the bare
`list[x509.Certificate]` to pass straight into
`verify_credential(..., x5c_trust_anchors=...)`. **No new verification surface** —
trust lists are an *anchor source*, and `openvc.x5c` remains the path validator.

### D2 — Split parsing (core) from XML-signature verification (out of core)
Two clearly separated responsibilities:

- **Anchor parser (core, stdlib, hardened).** Parse a TL XML document into typed
  records: the `SchemeInformation` (operator, issue/next-update, the "pointers to
  other TSL" for the LOTL) and the `TrustServiceProvider` → `TSPService` list with
  their `X509Certificate`s. Uses the stdlib XML parser under strict hardening
  (see D4). No signature logic here.
- **Signature verification: injected callback, fail-closed (core defines only the
  interface).** `consume_trust_list(...)` takes a
  `verify_signature: Callable[[bytes, Sequence[x509.Certificate]], None]` that is
  handed the **raw TL bytes** and the **expected signer certificate(s)** (from the
  parent LOTL pointer, or caller-pinned for the LOTL itself) and must raise on any
  failure. If it is `None`, consumption **fails closed** — a TL is never trusted
  unverified. Core ships the *interface*, not an XAdES implementation.

### D3 — An optional `[trustlist]` extra ships a reference XAdES verifier
So the batteries-included path exists without forcing the dependency, an optional
extra (`pip install openvc-core[trustlist]`, pulling `signxml` — which sits on
`lxml` + `cryptography`) provides `openvc.trustlist.xades.verify_xades_enveloped`,
a ready `verify_signature` callback that checks the enveloped XAdES signature and
that the signing cert is (one of) the expected signer certs. Core never imports it;
`consume_trust_list` without a callback and without the extra raises a clear
`TrustListSignatureUnavailable` (symmetric with `SchemaBackendUnavailable`).
*(Alternative considered: vendor a minimal enveloped-`SignedInfo` XML-DSig verifier
in core using only `cryptography`. Rejected for v1 — XAdES + XML C14N is a
notorious footgun (transforms, canonicalisation variants, cert-reference binding);
a mature library behind an extra is the honest choice. Revisit if the extra proves
too heavy.)*

### D4 — Hardened XML parsing (the parser sees attacker-influenced bytes)
The parser runs **before** the signature is verified (it must, to find the certs),
so it processes untrusted XML. Hardening, stdlib-only:
- Parse with a `xml.sax`/`ElementTree` parser configured to **forbid DTDs and all
  entity resolution** (no external entities, no parameter entities → blocks XXE and
  billion-laughs). Python's `expat` does not fetch external resources by default;
  we additionally reject any `DOCTYPE`.
- **Bound the input**: a max-bytes cap on the fetched TL (LOTL ~1 MB, national TLs
  up to a few MB — cap generously, e.g. 16 MiB, configurable) and a max element
  count, so a hostile document cannot exhaust memory.
- No namespace-prefix trust: match on **namespace URI + local name** only.
*(This is deliberately not `defusedxml`: the specific hardening we need — forbid
DTDs, cap size — is a few lines on the stdlib parser, and adding a dependency for
it contradicts the dependency-light invariant. Documented as a conscious choice.)*

### D5 — Trust flows from a caller-pinned LOTL signer down
There is **no implicit root** (consistent with `x5c` shipping no root store and
EBSI trusting only caller-chosen RootTAOs). The caller pins the **LOTL signer
certificate(s)** — the Commission keys, published out-of-band in the OJEU — as the
sole trust input. From there:
`caller-pinned LOTL signer → verify LOTL sig → LOTL pointers vouch for each
national TL's signer certs → verify each national TL sig → TL vouches for its
service X.509 certs`. Every hop is signature-gated; an unpinned or mismatched
signer breaks the branch.

### D6 — Fail-closed aggregation, with per-TL diagnostics
Walking ~30 national TLs, some will be unreachable, expired (`NextUpdate` passed),
or fail signature verification. The walk is **fail-open-per-anchor is forbidden**:
a TL that cannot be fetched or verified contributes **zero** anchors and is
recorded in a `problems` list on the result — never silently trusted, never
aborting the whole walk. The caller gets the anchors that *did* verify plus an
explicit account of what didn't. Selection filters (by `ServiceTypeIdentifier`,
e.g. `…/Svctype/CA/QC`; by `ServiceStatus` = `…/Svcstatus/granted`; by territory)
are applied during aggregation.

### D7 — Provider interface + SSRF-guarded fetch + short TTL cache
Fetching a TL is injected (`Callable[[str], bytes]`), so the caller supplies the
transport and SSRF policy; the blessed default reuses `openvc.fetch.https_bytes_fetch`
(https-only, private ranges blocked, IP-pinned). A TL declares its own validity
(`NextUpdate`); caching is a short client-side TTL bounded by `NextUpdate` (same
spirit as ADR-0001), so anchors refresh when a Member State updates its list.

### D8 — Pinned to recorded fixtures
Conformance is pinned by **recorded real vectors**, not synthetic XML: a trimmed
real LOTL and one or two real national TLs (kept small — a couple of TSPs each) as
golden fixtures, plus their real signer certs. Offline tests exercise parsing,
selection, fail-closed aggregation, and the injected-verifier contract with a stub;
the XAdES `[trustlist]` extra gets its own opt-in test verifying a recorded TL
signature for real. An opt-in `OPENVC_TRUSTLIST_LIVE=1` smoke test fetches the live
LOTL (mirrors the EBSI live test).

## Proposed surface (sketch, for review)

```
openvc/trustlist/
  __init__.py        # re-exports
  model.py           # TrustList, TrustServiceProvider, TrustServiceAnchor,
                     #   TslPointer, TrustListProblem  (frozen dataclasses)
  parse.py           # parse_trust_list(xml: bytes) -> TrustList   (hardened stdlib XML)
  consume.py         # consume_trust_list(...) / walk_lotl(...) -> TrustAnchorSet
                     #   (fetch + inject verify_signature + fail-closed aggregate)
  errors.py          # TrustListError, TrustListParseError,
                     #   TrustListSignatureUnavailable, TrustListSignatureError
  xades.py           # [trustlist] extra only: verify_xades_enveloped callback (signxml)
```

Public entry points (names TBD in review):
```python
from openvc.trustlist import walk_lotl, ServiceType, ServiceStatus

anchors = walk_lotl(
    lotl_url="https://ec.europa.eu/tools/lotl/eu-lotl.xml",
    lotl_signer_certs=[commission_cert],            # D5: caller-pinned root
    verify_signature=verify_xades_enveloped,        # D2/D3: injected, fail-closed
    fetch=https_bytes_fetch,                         # D7
    select=Select(service_types={ServiceType.QC_CA},
                  statuses={ServiceStatus.GRANTED}),
)
verify_credential(vc, x5c_trust_anchors=anchors.certificates)   # D1
```

## Consequences

- New optional extra `[trustlist]` (`signxml`); core stays `cryptography` + `pyjwt`.
- The verifier can now anchor eIDAS/EUDI `x5c` (and HAIP `x509_hash`) issuers in the
  EU-recognised roots, not just a hand-managed anchor list.
- The stdlib-XML hardening is security-critical; it gets dedicated adversarial tests
  (XXE attempt, DTD/entity bomb, oversize, namespace spoofing).
- Fixtures are a point-in-time snapshot; a `re-fetch periodically` caveat applies as
  for EBSI (ADR-0001).

## Resolved in review

1. **XAdES:** ship both — the injected-callback interface in core *and* an optional
   `[trustlist]` extra (`signxml`) with a reference verifier. Both landed (PR 2 added
   the extra).
2. **Scope:** two PRs (see *Phasing* above) — parser + walk + fixtures first, the
   `[trustlist]` XAdES extra second.
3. **Selection defaults:** default to `ServiceStatus.GRANTED` + qualified-CA service
   types (`ServiceType.CA_QC`); the caller can broaden (`select=None` returns every
   service with its metadata).
