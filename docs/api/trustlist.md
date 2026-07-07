# EU Trusted Lists

`openvc.trustlist` consumes the EU **List of Trusted Lists (LOTL)** and the national
Trusted Lists it points at (eIDAS 2.0 / EUDI, ETSI TS 119 612) as a source of
**X.509 trust anchors** for the verifier. `walk_lotl(...)` returns a
`TrustAnchorSet` whose `.certificates` feed the existing X.509 path directly — it
adds no verification surface; [`openvc.x5c`](dids-keys.md) stays the path validator.

```python
from openvc import verify_credential
from openvc.trustlist import walk_lotl
from openvc.fetch import https_bytes_fetch

anchors = walk_lotl(
    "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
    lotl_signer_certs=[commission_cert],     # caller-pinned root — no implicit trust
    verify_signature=my_xades_verifier,      # injected, fail-closed
    fetch=https_bytes_fetch)
verify_credential(vc, x5c_trust_anchors=anchors.certificates)
```

Trust is **caller-pinned** (the LOTL signer certs), **fail-closed** (a list that
cannot be fetched, verified, or is expired contributes zero anchors and is recorded
in `problems`), and **selective** (default: `granted` qualified-CA services). XML
parsing is hardened stdlib (no DTD/XXE, bounded); XML-signature (XAdES) verification
is an **injected callback** kept out of core. See
[ADR-0003](../adr/ADR-0003-eu-trusted-lists.md).

::: openvc.trustlist
