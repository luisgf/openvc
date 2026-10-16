# ADR-0009 — EBSI Core API v1, and how `openvc_ebsi` trusts a production node

**Status:** Proposed — a design for the maintainer to decide. It ships no code and changes
nothing under `src/`.
**Date:** 2026-10-16
**Context owner:** `openvc_ebsi.http`, `openvc_ebsi.versioning` (and a future
`openvc_ebsi.nodes`)
**Milestone:** [Conformance & production readiness](https://github.com/luisgf/openvc/milestone/11)
— refs [#113](https://github.com/luisgf/openvc/issues/113)
**Extends:** ADR-0001 (HTTP client, host allow-list, TTL cache). **Applies:** the splitting
rule of ADR-0007 — attacker-controlled bytes that must be verified fail-closed are
openvc's; anything with a lifetime, a socket or a deployment policy is the consumer's.

## Summary

EBSI replaced nine per-service pilot APIs with one **EBSI Core API v1** and, in the same
move, stopped publishing a host to call. A client now picks a *node* from a **Trusted Nodes
List (TNL)**: a JSON document signed with OpenPGP. That moves the question #113 asked
("add the production hostname to the allow-list") to a different one: **what makes a
hostname trustworthy, and who decides?**

What the investigation found, in order of weight:

1. **The wire format barely moved; the trust model did.** The Core v1 read shapes for the
   DID document, issuer, attribute list and attribute match the v5 shapes openvc_ebsi
   parses today; the sampled bodies differ by one field the recorded v5 fixtures lack
   (`parentAttributeId`). The recorded v1 bodies parse through the existing `TirV5` /
   `DidRegistryV5` logic when fed from memory. What changed is the URL layout, a per-node
   host, the error `type`, and **where the host comes from**.
2. **The TNL is fully specified, and verifiable with what is already installed.** Every
   key and every signature in the chain is v4 OpenPGP ECDSA over NIST P-256 with SHA-256.
   A throwaway verifier (about 180 uncompressed lines, standard library plus
   `cryptography`'s ECDSA) accepted the real chain in 8 ms and rejected every tampered
   variant. No PGP library is needed.
3. **A signed list authenticates the operator, not the data.** EBSI registry responses are
   unsigned JSON served by whichever node you reach. The TNL narrows "any host on the
   internet" to "one of 45 approved nodes"; it does not make a dishonest node's DID
   document true. This is a residual risk the library cannot close and the ADR says so.
4. **Two measured facts stop the "just re-point" plan.** The TNL's `pilot` nodes behave as a
   different ledger from the legacy pilot (`did:ebsi:zZeKyEJf…`, the DID every recorded
   fixture uses, answers 404 on them), and the RootTAO accreditations served by prod and
   preprod are signed `ES256K`, which the JOSE allow-list rejects, so **recursive trust
   cannot verify a Core v1 root today**. The second is a maintainer decision, not an
   ADR decision.

**Recommendation (details in D1–D8):** keep the explicit allow-list as the primitive
(Option A); add a **pure, stateless TNL verifier** to `openvc_ebsi` built on a hand-rolled,
ECDSA-only OpenPGP reader (Option C), vendoring **only the Europeum anchor, never the
list** (rejecting B); defer a PGP-library extra (D) and reject pattern allow-lists (E);
leave fetch, refresh and persistence to the consumer, with an optional thin helper; add
`DidRegistryCoreV1` / `TirCoreV1` adapters and a distinct `legacy-pilot` environment, and keep
the v5 lane until EBSI retires it. Eight open questions need the maintainer.

## Context

Marking used below: **[doc]** = stated in EBSI's published documentation or specification
file; **[measured]** = observed during this investigation on 2026-10-16; **[brief]** =
reported in the task brief and not re-verified here; **[inference]** = a reading, not a fact.

### What changed at EBSI

- **[doc] One API.** The hub's migration guide
  (<https://hub.ebsi.eu/api/migration-guide>, read 2026-10-16; its source is the public GitLab
  project `europeum/public/hub`, `website/docs/api/migration-guide.mdx`) maps nine
  separately versioned services to a single **EBSI Core API v1**, version `1.0.0`. The
  newest changelog entry, dated 2026-10-01, is the only one that mentions it and describes
  an update to the Core API v1 contract, so v1 probably existed earlier **[inference]**
  (`website/docs/api/changelog.mdx`; the published changelog page itself was not fetched).
  The published migration guide matches the repository source (spot check).
- **[doc] Machine-readable spec exists, and is public.** OpenAPI 3.1, `info.version` 1.0.0,
  licence field EUPL-1.2:
  <https://gitlab.com/europeum/public/hub/-/blob/main/website/api/core/openapi.yaml>
  (generated from `openapi.source.yaml` beside it; its `servers` list names pre-production
  only). It was read for the spec and nothing was copied. A copy hosted on hub.ebsi.eu was
  not looked for.
- **[doc] URL layout.** Base is `https://api-<env>.ebsi.<node operator's domain>/v1`
  (pilot, preprod) with the operator's own domain; paths lose the per-service version and
  the `trusted-` prefix. The reads openvc_ebsi uses:

  | openvc_ebsi call | Legacy pilot (v5) | Core API v1 (under `/v1`) |
  |---|---|---|
  | DID document by DID | `/did-registry/v5/identifiers/{did}` | `/did-registry/identifiers/{did}` (+ `contractAddress`, `valid-at`) |
  | Issuer record | `/trusted-issuers-registry/v5/issuers/{did}` | `/issuers-registry/issuers/{did}` |
  | Attribute list (the `attributes` link in the issuer body) | `…/issuers/{did}/attributes` | same suffix under `/issuers-registry` |
  | Attribute (the `href` of each list item; latest revision) | `…/attributes/{id}` | same suffix under `/issuers-registry` |
  | Not used today | `…/attributes/{id}/revisions[/{rev}]`, `/issuers` list | same suffixes; plus `/alive`, `/<registry>/details` |

  `TirV5.parse_issuer` never builds a `/revisions` path; it follows each item's `href`.
- **[doc] Behaviour changes that touch a reader.**
  - `self` and `links` URLs now carry `/v1/` and no per-service version. **[measured]** they
    also carry the *answering node's own host*, not a canonical one (11 responses, 8 hosts).
  - `page[after]` stays a 1-based page number; `page[size]` is capped at 50.
  - `contractAddress` now really selects a registry instance (the pilot ignored it). Omitted,
    the environment default is used; a wrong one is `400 Invalid Contract Address`.
  - DID content negotiation is kept: only an `Accept` of exactly `application/did+json`
    returns the `@context`-free form; anything else acceptable, `*/*` included, returns
    `application/did+ld+json`; an unsatisfiable `Accept` is 406. **[measured]** the client's
    existing `Accept` (ADR-0001 D10) got `application/did+ld+json` and no 406 on every v1
    read, so D10 holds unchanged.
  - Errors are RFC 9457 Problem Details with a stable `type` of the form
    `urn:ebsi:problems:<slug>`, replacing `about:blank`; callers should match on `type`, not
    `title` or `detail`. **[measured]** `urn:ebsi:problems:identifier-not-found` on a 404.
    405 and 406 are documented on every path.
  - Rate limit: 20 requests per second per client IP (`website/docs/api/rate-limit.mdx`).
    `GET /v1/alive` returns `{"health_global":1}` (200) or `{"health_global":0}` (503) and is
    cached by the node for up to five minutes.
- **[doc] Environments** are `pilot`, `preprod`, `prod`. The nine old APIs are listed on the
  hub as legacy, "available on the Pilot environment only". No retirement date appears in
  the migration guide, the API index or the changelog.
- **[brief] Not re-verified, no budget left for it:** `api.ebsi.eu` resolves to AWS and
  presents a self-signed certificate; `api-conformance.ebsi.eu` times out; the ebsi.eu site
  announces an "EBSI Ecosystem Roadshow & Business Launch" in Bucharest on 2026-10-22
  (single source; a web search found no corroboration; treat it as unverified). No SLA,
  pricing or onboarding document has been found. For the earlier state see #113's 2026-07
  comments.

### What the Trusted Nodes List is

Sources: the public repository <https://gitlab.com/europeum/public/trusted-nodes-list> (README,
`public/`), the files served at <https://tnl.ebsi.eu>, and the hub's reference verifier
`website/scripts/tnl.mjs` (JavaScript, uses the `openpgp` npm library; read, not copied).

```text
Europeum key-list key  (pinned out of band; the only thing a verifier trusts up front)
      | signs trusted-keys.json.sig            (covers the 1811 bytes of trusted-keys.json)
      v
trusted-keys.json      (version, threshold, custodian public keys)
      | the custodians sign tnl.json.sig       (covers the 7068 bytes of tnl.json)
      v
tnl.json               (version, keysVersion, issued, expires, nodes per environment)
```

Publisher rules **[doc]** (README "Verify the list"): a signature counts only if it is valid,
by an allowed key identified by its *primary* fingerprint, ECDSA with SHA-256/384/512, over
a binary document; any invalid signature rejects the file; unknown signers are ignored; a key
signing twice counts once; at least `threshold` distinct custodians are needed. The list must
validate against a published JSON Schema, `expires` must be in the future and at most 90 days
after `issued`, `issued` may not be in the future (5 minutes of skew), `keysVersion` must not
exceed the key list's `version`, `version` must exceed the last accepted one, and every node
URL must be a bare `https://` origin (no path, port or credentials) that starts with its
environment's prefix (`https://api-pilot.ebsi.`, `https://api-preprod.ebsi.`,
`https://api.ebsi.`) and appears once. Fail closed; keep the last accepted list until its own
`expires`; refresh about hourly with `If-None-Match`. Never download the pinned key at runtime.
The README says the key-list key is a stopgap until Europeum's qualified electronic seal
replaces it, at which point "only Steps 1 and 3 change".

**[measured] The live chain, 2026-10-16:**

| Artifact | Facts |
|---|---|
| `tnl.json` | version 4, `keysVersion` 1, issued 2026-10-06T13:33:18Z, expires 2027-01-04T13:33:18Z (exactly 90.0 days); pilot 23, preprod 12, prod 10 nodes (45 URLs, none under `*.ebsi.eu`); 27 distinct operator domains; 4 operators appear in all three environments, 1 in prod only |
| `tnl.json.sig` | two v4 signature packets, type 0x00 (binary), ECDSA / SHA-256, created 2026-10-06T13:36:43Z and 13:40:05Z, by the two custodians' primary keys |
| `trusted-keys.json` | version 1, `threshold` 2, two custodians: unanimity, no redundancy |
| custodian keys | v4, ECDSA over NIST P-256; created 2026-09-27 and 2026-09-30; primaries carry certify+sign; one block also has an ECDSA authentication subkey and an ECDH subkey (ignored); user IDs are named-person identities at a europeum.eu address (not reproduced here) |
| `trusted-keys.json.sig` | one v4 binary signature, ECDSA / SHA-256, created 2026-09-30T09:21:20Z, by the key-list key |
| `keylist-key.asc` | v4 ECDSA P-256, created 2026-09-30T09:13:54Z, fingerprint `ACCC82E5FC8902F114929481747CB65CFB7574F9`; the hub repo pins the same bytes and fingerprint |
| Expiry and rotation signals | **none inside OpenPGP**: no key-expiration or signature-expiration subpacket on any key or signature. Rotation is visible only as a new `trusted-keys.json` `version`; a change of the key-list key is out of band |
| Headers on the TNL | `cache-control: public, max-age=300, must-revalidate`, `etag`, `vary: Origin`, `application/pgp-signature` for `.sig` |

Every file served by `tnl.ebsi.eu` was byte-identical to the copy in the GitLab repository
(`cmp`). That shows the publisher is consistent across two channels; both are Europeum's, so it
is not independent authentication of the pin.

**[measured] Verification with standard-library parsing plus `cryptography`.** A scratch script
(not committed) parsed the packet framing (old-format headers, tags 2, 6, 13 and 14, v4
signature and key bodies, MPIs, subpackets), recomputed each custodian's v4 fingerprint
from its key material (all matched the listed ones), reproduced the signed digest per
RFC 4880 section 5.2.4, and verified with `ec.ECDSA` on the SEC1 point. Result: the pinned key
verified `trusted-keys.json.sig`; both custodians verified `tnl.json.sig`; 2 of 2 meets the
threshold; **accepted, 7.9 ms wall time**. Negative controls, all rejected: a changed host name
in `tnl.json`, one flipped bit, an appended newline, one flipped bit inside a signature's `s`
MPI (rejected by ECDSA itself, past the 16-bit hash-prefix check), a signature checked against
the wrong key, `tnl.json.sig` offered for `trusted-keys.json`, and only one of two signatures
(below threshold). The same signature twice counts as one signer. Editing the *unhashed*
issuer key ID changed nothing, because the script identifies the signer only from the hashed
issuer-fingerprint subpacket (type 33) and never from the attacker-editable unhashed area.
The parsing and verifying functions measured 142 + 41 lines, uncompressed, with comments and
diagnostics; a production version of the narrow profile below is estimated at 150 to 250
lines, plus tests **[inference]**.

### What `openvc_ebsi` does today

- `EBSI_HOSTS` maps `pilot -> api-pilot.ebsi.eu`, `conformance -> api-conformance.ebsi.eu`,
  `production -> api.ebsi.eu`; `for_ebsi(env)` seeds an https-only allow-list from it, and the
  wiki (`Trust.md`) and `tests/test_ebsi_verifier.py` pin those names.
- The guard matches the **host name only** (no port, no address check); the TIR adapter
  compensates by pinning `attributes`, each `href` and `links.next` to the listing's exact
  `scheme://host:port` (`_origin`, #172, #253). Redirects are off. A registry walk therefore
  cannot leave its node, and nothing in it needs changing for Core v1.
- Adapters live behind `versioning.py`: `DidRegistryV5`, `TirV4`, `TirV5`.
- The accreditation JWTs inside TIR records are read two ways: `peek_claims` (no signature
  check) in single-level mode, and `VcJwtProofSuite.verify` per hop in recursive mode
  (`trust_anchors=`).
- The weekly smoke (`live-ebsi.yml`, `OPENVC_EBSI_LIVE=1`, `test_live_resolve`) resolves a DID
  document, by default `did:ebsi:zZeKyEJf…` through `for_ebsi("pilot")`, i.e. on
  `api-pilot.ebsi.eu`; the environment and DID can be overridden by two environment
  variables. It does not read the TIR.

### What a probe of the live Core API showed

25 GET requests, the whole budget; the complete list is in the appendix. TLS verification
passed on all of them, no redirects were followed, no credentials were sent, nothing was
written.

| Question | Result **[measured]** |
|---|---|
| Which environments serve `/v1`? | Pilot (2 of 23 nodes tried), preprod (3 of 12), prod (4 of 10): every node tried answered `/v1` reads |
| Is the TNL `pilot` the legacy pilot? | **Evidently not.** `GET /v1/did-registry/identifiers/did:ebsi:zZeKyEJfUTGwajhNyNX928z` is a 404 `urn:ebsi:problems:identifier-not-found` on both pilot nodes tried, and one of them lists `total: 2` identifiers; the legacy host `api-pilot.ebsi.eu` still answers 200 for that DID on `/did-registry/v5/…` |
| What does each environment hold? | Preprod: 244 issuers, DID documents with real keys (a `secp256k1` and a `P-256` key). Prod: **one** issuer, `did:ebsi:z262SoSjWAqmXpaGmzqGnJoc`, whose DID document has an **empty `verificationMethod`** |
| Are nodes consistent? | The first-page issuer list was identical on 4 of 4 prod and 3 of 3 preprod nodes once each node's own host name was normalised |
| Shapes vs v5 | Issuer `{attributes, did, hasAttributes}`, attribute page `{items[{id, href}], links, pageSize, self, total}` with `links.next` pointing at the same page on the last page (the existing `seen` guard covers it), attribute `{attribute{body, hash, issuerType, parentAttributeId, rootTao, tao}, did}`. Fed from memory through the **unmodified** `DidEbsiResolver` + `TirV5` with the v1 URLs, the prod issuer produced a correct `IssuerRecord` (RootTAO, `VerifiableAuthorisationForTrustChain`) and the DID document parsed |
| `id` vs `hash` | The list item `id` differs from `attribute.hash` in both v1 attributes sampled (prod and preprod). The adapter must not assume they are equal |
| Algorithm of the roots | Both the prod and the preprod RootTAO accreditation JWTs are `alg: ES256K`. `VcJwtProofSuite.verify` on the preprod one raised `UnsupportedAlgorithm: algorithm 'ES256K' is not permitted` |
| Hosts inside accreditations | `credentialSchema.id` names `api-prod.ebsi.eu` (prod) and `api-test.ebsi.eu` (preprod): hosts in **no** TNL environment. openvc does not follow them today |
| Cache validators | None on any node response (no `Cache-Control`, `ETag`, `Last-Modified`), so ADR-0001 D1 and D2 still hold. Only the TNL and the docs site send them |
| Latency | Mostly 0.13 to 0.4 s; outliers of 6.5 s (the first request to one prod node) and 3.4 s (a prod issuer read). ADR-0001 D5's 10 s timeout stays right |
| Failover hazards | `api.ebsi.stsisp.ro` answered 200 to the `openvc-core/1.35.1` User-Agent, while the brief reports a 403 from it to curl's default agent: **[inference]** a node can refuse a client on its User-Agent, so a 403 is a reason to fail over, not to abort. Two hosts under one operator (`edelivery.lt`, prod and preprod) set a `SRV_ID` cookie, i.e. a load balancer sits behind that host name |

## Decision drivers

From `CLAUDE.md` and the earlier ADRs; each option is judged against them.

1. **EBSI stays read-only.** Nothing here may add a write path.
2. **SSRF guards stay.** https-only, an allow-list on every request including links and
   redirects. Whatever builds the allow-list becomes part of the trust root.
3. **No state, no transport (ADR-0007).** Replay protection needs state; the obligation must
   appear in a signature, not in prose.
4. **Version specifics live behind adapters.** No `if version ==` ladders; a new API
   version is a new adapter plus a golden fixture.
5. **Dependency-light.** Core is `cryptography` + `pyjwt`; CBOR/COSE is already hand-rolled;
   anything heavier sits behind an extra.
6. **Fail closed, and golden fixtures are the drift alarm.** Conformance is pinned by
   recorded real vectors, not synthetic shapes.
7. **Do not widen the JOSE algorithm allow-list casually.**
8. **Public API stability.** `EBSI_HOSTS` / `for_ebsi` names are documented; breaking them is
   2.0 work (#74).

## Options considered

### A — Caller-supplied explicit allow-list (today), plus documentation and a helper

`EbsiHttpClient(allowed_hosts=…)` stays the primitive. Add a recipe for choosing nodes
(the README's `gpg` procedure, or `openpgp` in the consumer's own stack) and, optionally, a
helper that turns a list of origins into a client.

- *Security:* the trust decision stays with the operator, who is best placed to make it.
  No new parser in openvc.
- *Cost:* every integrator re-implements the verification, or skips it and pastes hostnames
  from a web page; nothing stops them from pasting `api.ebsi.<anything>`. The TNL's
  protections (threshold, expiry, rollback) are then only as good as each integrator.
- *Verdict:* necessary, not sufficient. It is the primitive the other options feed.

### B — A node snapshot vendored in the package, refreshed per release

- *Security:* trusts the wheel (PyPI) for a security-relevant list, with no signature check at
  use, unless the signatures are verified too, which is Option C with extra steps.
- *Cost:* the list **expires in at most 90 days** (this one on 2027-01-04). openvc releases on
  no fixed cadence, so a release older than 90 days ships an expired list; strict expiry makes
  the plugin fail closed for every user who has not upgraded, and lax expiry reintroduces the
  stale-list attack. Nodes join and leave; a pinned snapshot is wrong the day after release.
- *Verdict:* **rejected.** The only parts worth vendoring are things that do not expire (the
  anchor, a version floor; D3).

### C — Runtime fetch of the list with signature verification, hand-rolled minimal OpenPGP

- *Security:* the chain is verified from a pinned anchor on every acceptance; the server,
  DNS and network path are untrusted (the publisher's own advice). Zero new dependencies:
  `cryptography` is already core.
- *Parser surface, honestly:* the narrow profile is v4 only; packet tags 2, 6, 13 and 14
  only; public-key algorithm 19 (ECDSA) only; curves P-256/P-384/P-521; hash algorithms
  SHA-256/384/512; signature type 0x00; no partial lengths; every length bounded; any other
  construct is a typed error. Bytes parsed *before* any authentication are just the two
  detached-signature files (a few hundred bytes each; cap them at 4 KiB). The custodian key
  blocks are parsed only after `trusted-keys.json` has verified against the pinned key, so
  they are authenticated bytes. This is smaller than the CBOR/COSE the project already
  hand-rolls, and it can be fuzzed with the existing hostile-input harness.
- *Deliberately not done* (and what each omission costs): self-signature and binding checks,
  user IDs, subkeys, trust models, key expiry and revocation inside the key block, text
  signatures, v5/v6 packets. The reference JavaScript verifier uses a full OpenPGP library
  and presumably honours an expiry or revocation packet inside a custodian block; a minimal
  reader would ignore it **[inference]**. The TNL protocol's own revocation path is a new
  `trusted-keys.json`, and none of the current blocks carries such a packet, so the gap
  should not matter in practice; a cheap rule closes it anyway: **reject** any key block
  that contains a revocation-type signature or a key-expiration subpacket, rather than
  ignoring it.
- *Verdict:* the target.

### D — The same, with an optional extra on a PGP library

Candidates, from PyPI metadata read 2026-10-16 (no code audit):

| Package | Latest (upload) | Licence | Note |
|---|---|---|---|
| PGPy | 0.6.0 (2022-11-24) | BSD-3-Clause | Beta; no release in nearly four years; forks `pgpy13` 0.6.1rc1 (2025-03) and `pgpy-dtc` 0.1.1 (2024-12, EUPL-1.2, alpha) exist, the first with the stated aim of Python 3.13 compatibility |
| pysequoia | 0.1.35 (2026-08-30) | Apache-2.0 | Beta; active; native Rust extension over Sequoia-PGP |
| python-gnupg | 0.5.7 (2026-09-29) | BSD | Wraps the system `gpg` binary through subprocesses; needs GnuPG 2.2+ on the host; stateful keyrings |

- *Benefit:* tolerance to an OpenPGP profile change (v6 keys, new algorithms).
- *Cost:* the whole OpenPGP universe becomes attack surface to verify three ECDSA signatures;
  a native wheel or a system binary becomes a deployment requirement; the one pure-Python
  option is stale. The publisher already fixes the profile in prose and in its own code
  (ECDSA, three hashes, binary), so a profile change would be announced and would also change
  the anchor step.
- *Verdict:* **defer.** Revisit if EBSI changes the profile, or if Europeum's qualified-seal
  step (open question 7) needs a library anyway.

### E — A pattern allow-list such as `api.ebsi.*`

- *Why it is tempting:* every node name starts `api.ebsi.` (prod), `api-pilot.ebsi.` or
  `api-preprod.ebsi.`, which is what the publisher's own content rules check.
- *Why it fails:* the part after `ebsi.` is whatever domain the operator owns, so the pattern
  authenticates nothing. `api.ebsi.attacker.example` needs only a domain the attacker
  controls, a public certificate for it (domain validation), and a registry response; the
  allow-list would admit it. A suffix rule fails the other way: **none of the 45 node hosts
  is under `ebsi.eu`**, and the 27 operator domains include second-level and
  third-party zones (`gov.ro`, `node1.nask.pl`, and one pilot node under
  `trafficmanager.net`, a shared cloud zone with a different takeover profile from an
  operator-owned domain; **[inference]**, not tested).
- *Verdict:* **rejected.** The prefix check is useful only *after* a list has been
  authenticated, where the publisher uses it so that a node cannot pose as another
  environment (D2 keeps it for that reason).

### At a glance

| Option | What authenticates the node set | New code in openvc | New dependency | Expiry hazard | Verdict |
|---|---|---|---|---|---|
| A explicit allow-list | the operator's own decision | none (docs, optional helper) | none | none | primitive, keep |
| B vendored snapshot | the wheel | small | none | **ships expired within 90 days** | rejected |
| C fetch + minimal OpenPGP | pinned anchor, custodian threshold | one pure function, ~150-250 lines | none | handled (typed error) | **target** |
| D fetch + PGP library | the same | less parser, more glue | one heavy extra | handled | defer |
| E pattern | nothing | tiny | none | none | rejected |

## Decision

Proposed; each item stands or falls separately so the maintainer can take part of it.

**D1 — Keep A as the primitive, and tighten it later.** `EbsiHttpClient` keeps taking an
explicit set of hosts; everything else in this ADR produces such a set. Document the recipe for
integrators who want to do the verification elsewhere. A follow-up should make the guard
match the origin (host and port 443), because the TNL guarantees bare `https://host` URLs.

**D2 — A pure, stateless TNL verifier in `openvc_ebsi`, not in core.** Bytes in, frozen
result out, no I/O. By ADR-0007's rule the verification of attacker-influenced bytes is
openvc's; fetching, refreshing and persisting are the consumer's. The inputs are the four
byte strings, the pinned anchor, an injected `now`, the environment wanted, and **required
keyword arguments for what must persist**: the last accepted list version and the last
accepted key-list version (each `None` meaning "first run: a replay of an older list is
possible once", stated in the docstring). The output carries the version, `issued`,
`expires`, and the nodes of the requested environment as validated origins. It lives in
`openvc_ebsi` because only EBSI uses it and the dependency rule forbids core importing
upward; it adds no dependency. It enforces the publisher's rules exactly as listed in the
context, and additionally:

- refuses duplicate or non-ASCII hosts, and any URL that is not a bare origin (consistent
  with the ASCII-only host policy, v1.31.2);
- applies rollback protection to the **key list as well as the node list**: `trusted-keys.json`
  carries no expiry, so a stale, validly signed key list from before a custodian rotation could
  otherwise be replayed with an old, compromised custodian key **[inference; the README rolls
  back only `tnl.json`]**;
- treats a custodian key block containing a revocation signature or a key-expiration
  subpacket as invalid (Option C, last bullet);
- raises typed errors under `EbsiError` (signature, threshold, expiry, not-yet-valid, rollback,
  malformed, environment-missing) and never returns a partially verified list.

**D3 — Vendor the anchor and a version floor, never the list.** The wheel carries the
key-list key's public point and its v4 fingerprint (pinning the *key material*, not only the
SHA-1 fingerprint) and, optionally, an integer **floor** for the list version, raised at each
release. A floor gives a stateless caller a rollback bound without any list to expire, and
it can only reject, never admit (so it must never exceed a version EBSI has really
published). The anchor must be overridable by the consumer: the README
announces a change of the root (a qualified seal) and it is out of band. The ceremony that
makes the shipped pin trustworthy is a maintainer decision (open question 2).

**D4 — Fetching and refreshing: a thin, optional helper; persistence stays with the consumer.**
Two additions to `openvc_ebsi.http`: a bytes-returning GET (the signature files are binary;
`get_json` would reject them) with the same caps, deadline and host guard, and a helper that
fetches the four documents from `tnl.ebsi.eu` using a client allow-listing **that host alone**,
never the node set, so a poisoned node list cannot widen where the list itself is fetched.
It honours `ETag`/`If-None-Match` and the publisher's hourly guidance; it keeps nothing. A
deployment that wants a daemon, a database or a sidecar writes it.

**D5 — From verified nodes to a client, with single-node walks.** A constructor takes the
verified result and returns clients or resolvers per node; node choice is an injected policy
(default: random among nodes that answer `/v1/alive`), failover happens **between** resolves
and never inside a registry walk. The existing `_origin` pin already refuses a walk that
tries to leave its node; failover must restart the walk on the next node. Treat
transport errors, 429, 5xx and 403 as node failures to fail over from; treat a 404 as
authoritative for that node only (open question 5).

**D6 — Core v1 adapters and an honest environment table** (names only; next section).

**D7 — Say what the TNL does not give.** In the wiki and the threat model: the list
authenticates the *operator*, not the *content*. A dishonest listed node can serve another key
for a DID and forged accreditations, and openvc would verify them. The mitigation that exists
is cross-node comparison of the trust-critical reads, which is a policy with a cost (twice the
requests against a 20 requests/second/IP limit); it belongs to the consumer, with a documented
helper at most. The chain's real root is the single key-list key: with it, an attacker can
substitute `trusted-keys.json` (custodians and threshold) and then sign any list; the
two-custodian threshold only protects against compromise of the custodians.

**D8 — Do not decide ES256K here.** See open question 3. Until the maintainer decides,
single-level trust (which reads the accreditation without verifying its signature, the
registry being the trust anchor) works on Core v1 data; recursive trust (`trust_anchors=`) fails
closed on an `ES256K` root, and on the prod seed it could not succeed anyway because the root's
DID document carries no verification method.

### Security properties this gives, and does not

| Gives | Does not give |
|---|---|
| The node set comes from a list signed by a threshold of known custodians under a pinned anchor | Honesty of a listed node; authenticity of registry content |
| Fail-closed on any malformed, expired, not-yet-valid, rolled-back or under-signed list | Revocation of a node between list versions (bounded by the refresh interval and the 90-day maximum) |
| Replay bounded by a persisted version and a shipped floor; key-list replay too | Protection on the first run of a stateless caller beyond the floor |
| Hosts constrained to ASCII bare origins, one per row, with the environment prefix as a sanity check | Defence against DNS or certificate compromise of one listed host name |
| Offline and deterministic: `now` is injected, nothing is fetched by the verifier | A defence if the key-list key is compromised or the pin is wrong |
| Zero new dependencies; the only bytes parsed before authentication are two small signature files | Anything about EBSI operators' availability or SLA (none published) |

## Where each design can be attacked

| Mechanism | Attack | Outcome | Mitigation in this proposal |
|---|---|---|---|
| Allow-list built from the list (C) | Forged list pointing at attacker hosts | Needs the key-list key or, today, both custodian keys; an attacker holding only retired custodian keys must also replay an old `trusted-keys.json` | Signature chain; rollback protection on both versions |
| Same | Stale list replayed to a stateless client | Old nodes trusted until that list's `expires` (at most 90 days) | Persisted version, shipped floor, strict `expires` |
| Same | Compromise of the key-list key | Total: substitute the custodians and threshold, then sign anything | Out of scope for openvc; keep the pin overridable; watch the qualified-seal switch |
| Same | Custodian threshold of 2 of 2 | One lost custodian key blocks publication; no verifier risk | Publisher problem; noted for the maintainer |
| Pattern allow-list (E) | Any registrable domain shaped `api.ebsi.<x>` | Fully attacker-controlled "node" | Rejected |
| Redirects | A node 30x-ing to another host | Followed only if the client follows; it does not | `follow_redirects=False` stays; a 3xx is a node failure |
| DNS rebinding | A listed host name re-pointed at a private address | The guard is host-name only, no address check (threat model R4); the registry paths are fixed and DID-validated, so reach is a fixed GET, but it is still a GET from inside a network | Optional resolved-address guard reusing `openvc.fetch`'s rules (follow-up); it cannot stop an attacker who can also obtain a valid certificate |
| Dishonest node | Substitutes a DID document or accreditation | Verification proceeds on forged data | D7: cross-node comparison as consumer policy; not solvable by the list |
| Port on an allowed host | `https://listed-host:9200/…` | Host-only guard admits it | `_origin` pins links today; D1 follow-up to guard on origin |
| Node selection | Always the first listed node | Load concentration, one point of failure | Random among healthy; policy injected |
| 90-day expiry | Publisher stops reissuing | Every strict client fails closed at the expiry instant | Surfacing a typed error and a watch job; a documented grace policy is the consumer's |
| Node consistency | A lagging node 404s a new DID or serves an older key | A just-rotated key may be accepted briefly | Existing short TTL (ADR-0001 D2); 404 not treated as global |
| Cookie jar | `SRV_ID` sticky-routing cookie on the pooled `httpx.Client` | Harmless state; makes consecutive reads sticky to a backend | Note only; follow-up to disable the jar |
| Links inside accreditations | `credentialSchema.id` on `api-prod.ebsi.eu` / `api-test.ebsi.eu` | A future schema fetch must not assume node hosts | Keep schema fetching out of the node allow-list |

## Core v1 adapters and the environment table

Names only; no code is proposed in this ADR.

- `DidRegistryCoreV1` (a `DidRegistryAdapter`): the identifiers URL under `/v1/did-registry`;
  parsing is the shared W3C parser, unchanged. Optional `contractAddress` pass-through;
  never accepted from a response or a token, only from configuration.
- `TirCoreV1` (a `TirAdapter`): the issuer URL under `/v1/issuers-registry`; the `attributes`
  and `href` follow-ups carry over from `TirV5` (same shapes, same origin pin); reads
  `parentAttributeId` onto the model if the maintainer wants it; does not equate list `id`
  and `attribute.hash`.
- Registered as `"core-v1"` in `DID_REGISTRY_ADAPTERS` and `TIR_ADAPTERS` (not `"v1"`, which
  would collide with the older per-service `trusted-contracts-registry/v1` vocabulary). `TirV5`
  and `DidRegistryV5` stay as the legacy lane. `DidEbsiResolver.base` already takes a
  per-node base, so the resolver and the trust logic need no change.
- Problem Details: map `type` (`urn:ebsi:problems:*`) onto `HttpError`; ADR-0001 D7 asked for
  body detail and `http.py` still maps by status alone.
- **Environment table** (the `EBSI_HOSTS` successor): `legacy-pilot` (`api-pilot.ebsi.eu`,
  fixed host, the only place the recorded fixtures and the weekly smoke are valid),
  and `pilot`, `preprod`, `prod` as **node-derived** environments with no fixed host. The
  existing `conformance` is outside the TNL's scope. The existing `pilot` key and
  `production -> api.ebsi.eu` are the compatibility question: `pilot` today means the legacy
  lane under a name EBSI has since reused, and `production` names a host that, per the brief,
  serves no API. Open question 4.

## Migration plan

1. **Now, no code needed (A).** Publish the recipe; correct #113's checklist: there is no
   production hostname to add; the unit is a verified node list.
2. **Stage 1 (additive, one minor release).** Adapters plus golden fixtures; the pure
   verifier and `_openpgp` with fuzzing and fixed-clock tests; the `legacy-pilot` name.
3. **Stage 2.** Bytes-GET, the `tnl.ebsi.eu` helper, the node-based constructor and
   failover, the weekly workflow extended to the TNL and Core v1 preprod.
4. **Stage 3 (decision-gated).** ES256K (open question 3); environment-table clean-up with the
   2.0 window (#74).
5. **The v5 lane stays** until EBSI retires it. The migration guide gives no date and the
   legacy host still serves; the lane costs nothing to keep and the recorded fixtures remain
   its drift alarm. Re-check at each hub changelog entry.

## Fixtures plan

Golden fixtures are the drift alarm (invariant 6); the data to record exists now.

- **TNL chain, real vector.** `tnl.json`, `tnl.json.sig`, `trusted-keys.json`,
  `trusted-keys.json.sig`, `keylist-key.asc` as served on 2026-10-16 (public artifacts), plus
  derived negative vectors (tampered, single signature, wrong key, duplicate signer, appended
  byte). **Trap:** this list expires 2027-01-04; every test must inject a fixed clock inside its
  window or the suite goes red that day.
- **Core v1, preprod is the verifying fixture.** Record, from two nodes (for example
  `api-preprod.ebsi.grnet.gr` and `api-preprod.ebsi.incm.pt`, to prove cross-node identity):
  the issuers page, `did:ebsi:zmaEptEHQRAmkJnFV6ki3io` (DID document with `secp256k1` and
  `P-256` keys), its issuer record, attribute list and attribute `0dc6a111…`.
- **Core v1, prod is a shape fixture only.** One seeded issuer, `did:ebsi:z262SoSjWAqmXpaGmzqGnJoc`,
  with an empty `verificationMethod`; the content will change when real operators onboard, so
  mark the fixture as a seed snapshot and expect to replace it at launch.
- **Errors.** The 404 problem document from a pilot node (observed in this investigation,
  to be re-recorded); one 400 `invalid-contract-address`, one 405 and one 406 to record
  before the adapter lands (not measured here).
- **Legacy.** Keep `tests/fixtures/ebsi/*` untouched.
- **Do not** hand-edit recorded bodies to make a test pass; ids, hrefs and hosts are part of the
  evidence.

## Consequences

- openvc_ebsi becomes usable against production without a hard-coded host that is wrong,
  and the trust decision becomes inspectable: one function, one anchor, a known failure list.
- A small hand-written OpenPGP reader is new security-relevant code in the repository. It
  is bounded, fuzzable and fails closed, but it is ours to maintain; the alternative is a
  heavy dependency for three signatures.
- A release can carry stale knowledge in only two places, the anchor and the floor, neither
  of which expires.
- Consumers who ignore the persistence arguments get replay protection only up to the floor;
  the signature makes that visible, but it cannot make them pass the right value.
- The weekly smoke can no longer be "re-pointed": the legacy lane keeps its job and a second
  job (TNL + Core v1 preprod) is added, which needs a clock-aware verification step in CI.
- Recursive trust remains unavailable on Core v1 roots until open question 3 is decided.
- Dishonest-node risk is documented, not removed.

## What to watch

- **2026-10-22:** the reported EBSI Ecosystem Roadshow & Business Launch in Bucharest
  (single source, unverified here). Look for SLA, pricing, onboarding and access terms for
  automated readers, and for a prod announcement that changes the 20 requests/second limit.
- **2027-01-04:** the current `tnl.json` expires. Expect a new version before then; if none
  appears, every strict client fails closed. A CI job should warn at 14 days.
- **hub.ebsi.eu changelog** (<https://hub.ebsi.eu/api/changelog>) for Core API v1 amendments, a
  legacy retirement date, and anything touching DID Registry content negotiation.
- **TNL repository and `trusted-keys.json`:** a new `version`, a change of threshold or
  custodians, and the switch from the key-list key to a qualified seal (the README says only
  its Steps 1 and 3 change).
- **Prod content:** the single seeded issuer and its empty DID document; `ES256K` in the roots.
- **Wider EU context:** the EUDI timeline already tracked in the ROADMAP.

## Open questions (maintainer)

1. **Which parts of this proposal do you want?** Option C as a library function (D2), or
   documentation only (A), leaving the verification to each consumer for now?
2. **The pin.** Do you want a default anchor in the wheel (D3)? If so, what ceremony makes it
   trustworthy: the key's fingerprint agrees across the hub repository, the TNL repository and
   the served file, but all three are Europeum's. An out-of-band confirmation from
   Europeum, for example from the EBSI Support Office address in the OpenAPI contact block,
   would be stronger.
3. **ES256K (RFC 8812) in the JOSE allow-list.** Options: admit it behind an explicit opt-in on
   `VcJwtProofSuite`, as ML-DSA is; or keep it out and document that recursive trust is
   unavailable on Core v1. It is a `CLAUDE.md` invariant ("do not widen it casually"), `cryptography`
   supports secp256k1, and the DID documents sampled carry secp256k1 keys alongside P-256.
4. **Names and compatibility.** `for_ebsi("pilot")` means the legacy lane and the wiki documents
   it; `production` names a host that serves no API. Alias and deprecate now, or leave until
   2.0 (#74)? Is a `ValueError` on `for_ebsi("production")` acceptable as a bug fix?
5. **Multi-node agreement.** A documented consumer pattern, a helper in the plugin, or nothing?
   And is a 404 on one node authoritative?
6. **The shape of persistence.** Required `last_accepted_*` keyword arguments (the proposal), or
   an injected store callable in the style of the OID4VCI nonce store?
7. **The qualified-seal switch.** Stay out until Europeum publishes the signature format, or
   design the anchor interface now so it can take a second kind of root?
8. **Scope of the live smoke.** Add Core v1 preprod and TNL verification to the weekly workflow
   now, or after the prod launch? (Preprod is public, read-only and holds 244 issuers; the TNL
   pilot nodes hold almost nothing.)

## Proposed follow-up issues

Titles with one line each; none have been filed.

- `docs(ebsi): correct the #113 checklist and publish the node-trust recipe` — there is no
  production host to add; document the TNL verification for consumers (Option A).
- `feat(ebsi): DidRegistryCoreV1 and TirCoreV1 adapters with golden fixtures` — URL layout,
  `parentAttributeId`, Problem Details `type`; preprod two-node vectors.
- `feat(ebsi): pure Trusted Nodes List verifier with a minimal ECDSA-only OpenPGP reader` —
  rollback inputs, fixed-clock tests, fuzzing, the narrow profile, key-block rejection rules.
- `feat(ebsi): bytes GET and a tnl.ebsi.eu fetch helper` — separate one-host allow-list,
  `ETag`, size and deadline caps.
- `feat(ebsi): node-based client constructor with health check and single-node failover` —
  injected selection policy; walks never mix nodes.
- `fix(ebsi): environment table — legacy-pilot, node-derived pilot/preprod/prod` — resolves
  open question 4.
- `security(ebsi): allow-list on origin (host and port 443), not host name` — the TNL
  guarantees bare origins.
- `security(ebsi): optional resolved-address guard for list-derived hosts` — reuse
  `openvc.fetch`'s address rules; threat-model R4.
- `feat(jose): ES256K opt-in for EBSI accreditation chains` — decision-gated (open question 3).
- `ci(ebsi): weekly Core v1 preprod smoke and TNL expiry/version watch` — keeps the legacy
  v5 smoke; warns 14 days before `expires`.
- `docs(audit): update threat model R4 wording when the adapters land` — the allow-list
  line stays true until then.
- `feat(ebsi): disable the cookie jar on the pooled client` — sticky-routing cookies are
  state the client does not need.

## Appendix — what was called, and how to reproduce

Network use for this ADR, 2026-10-16: **25 GET requests to EBSI hosts** (the cap), all over https
with certificate verification on, no redirects followed, no credentials, no writes. The first
five used curl's default User-Agent; the other twenty sent `openvc-core/1.35.1`, with
`Accept: application/json, application/did+ld+json, */*;q=0.1` on all but the last (`text/html`).
Responses were treated as data
and parsed, never executed. Specification and documentation were read from the public GitLab API
(`gitlab.com`, not an EBSI host), library metadata from the PyPI JSON API, and one web search
found no corroboration of the launch event.

| # | Host and path | Status |
|---|---|---|
| 1-5 | `tnl.ebsi.eu` `/tnl.json`, `/tnl.json.sig`, `/trusted-keys.json`, `/trusted-keys.json.sig`, `/keylist-key.asc` | 200 each |
| 6 | `api.ebsi.edelivery.lt/v1/issuers-registry/issuers?page[size]=1` | 200 |
| 7 | `api.ebsi.iti.gr` same path | 200 |
| 8 | `api.ebsi.stsisp.ro` same path | 200 |
| 9 | `api.ebsi.incm.pt` same path | 200 |
| 10 | `api-preprod.ebsi.grnet.gr` same path | 200 |
| 11 | `api-preprod.ebsi.edelivery.lt` same path | 200 |
| 12 | `api-preprod.ebsi.incm.pt` same path | 200 |
| 13 | `api.ebsi.iti.gr/v1/issuers-registry/issuers/did:ebsi:z262SoSjWAqmXpaGmzqGnJoc` | 200 |
| 14 | `api.ebsi.iti.gr/v1/did-registry/identifiers/did:ebsi:z262SoSjWAqmXpaGmzqGnJoc` | 200 |
| 15 | `api.ebsi.iti.gr/v1/issuers-registry/issuers/<prod seed>/attributes` | 200 |
| 16 | `api-preprod.ebsi.grnet.gr/v1/issuers-registry/issuers/did:ebsi:zmaEptEHQRAmkJnFV6ki3io/attributes` | 200 |
| 17 | `api-preprod.ebsi.grnet.gr/v1/did-registry/identifiers/did:ebsi:zmaEptEHQRAmkJnFV6ki3io` | 200 |
| 18 | `api.ebsi.iti.gr/v1/issuers-registry/issuers/<prod seed>/attributes/<id>` | 200 |
| 19 | `api-preprod.ebsi.grnet.gr/v1/issuers-registry/issuers/<preprod root>/attributes/<id>` | 200 |
| 20 | `api-pilot.ebsi.grnet.gr/v1/did-registry/identifiers/did:ebsi:zZeKyEJfUTGwajhNyNX928z` | 404 |
| 21 | `api-pilot.ebsi.iti.gr` same path | 404 |
| 22 | `api-pilot.ebsi.grnet.gr/v1/did-registry/identifiers?page[size]=1` | 200 (`total` 2) |
| 23 | `api-pilot.ebsi.eu/did-registry/v5/identifiers/did:ebsi:zZeKyEJfUTGwajhNyNX928z` | 200 |
| 24 | `api.ebsi.iti.gr/v1/alive` | 200 |
| 25 | `hub.ebsi.eu/api/migration-guide` | 200 |

Download the chain (the same URLs, no authentication):

```bash
for f in tnl.json tnl.json.sig trusted-keys.json trusted-keys.json.sig keylist-key.asc; do
  curl -fsS --proto =https -o "$f" "https://tnl.ebsi.eu/$f"
done
gpg --show-keys --with-fingerprint keylist-key.asc     # expect ACCC 82E5 FC89 02F1 1492  9481 747C B65C FB75 74F9
```

Re-run the structural probe by parsing the packet framing (RFC 4880 section 4.2) of the two
`.sig` files and the armored blocks in `trusted-keys.json`, and the verification with
`cryptography.hazmat.primitives.asymmetric.ec` on the SEC1 point; expect two custodian
signatures at `threshold` 2. The probe scripts were scratch files and are deliberately not
committed.
