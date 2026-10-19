# EBSI node trust: where reads go and whom to believe

`openvc_ebsi` is read-only: it resolves `did:ebsi` and reads the EBSI registries through an
https-only host allow-list (see [Trust anchors](Trust)). Which hosts belong on that
allow-list stopped being obvious. **EBSI Core API v1 has no fixed production host.** A
client picks a *node* from a signed **Trusted Nodes List** (TNL), an OpenPGP-signed JSON
document served at <https://tnl.ebsi.eu>. This page says where reads go today, how to
obtain and verify the list, how to turn a verified list into an explicit allow-list, and
what a signed list does **not** prove.

Every dated statement below was measured or read on **2026-10-16** and comes from
[ADR-0009](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md),
which records the requests behind it. A dated statement is an observation, not a guarantee,
and this ecosystem is moving. Where the ADR gives no measurement, the text says *to be
measured*.

This page ships no node list, and ADR-0009 rejects vendoring the list in the library: a list
expires in at most 90 days. The library does ship both halves of the work. The fetch half is
`openvc_ebsi.http.get_tnl_files()`, which returns the four signed documents as unauthenticated
bytes through a client that allow-lists `tnl.ebsi.eu` alone. The verify half is
`openvc_ebsi.nodes.verify_node_list` ([#319](https://github.com/luisgf/openvc/issues/319)): a
pure, offline check of the chain with one pinned Europeum key-list key, described under
[Trust anchors](Trust). The sections below say what that verification entails, so you can judge
it, or do it yourself in your own stack.

## Where reads go today

There are two lanes, and `openvc_ebsi` reads one of them.

**The legacy pilot lane.** `api-pilot.ebsi.eu`, with per-service `v5` paths. It is the only
place the recorded fixtures and the weekly live smoke test are valid, and it is what
`for_ebsi()` reaches (its default, `legacy-pilot`; the older spelling `pilot` reaches it too and is deprecated). On 2026-10-16 it still answered 200 for
`did:ebsi:zZeKyEJfUTGwajhNyNX928z` on `/did-registry/v5/identifiers/…`. The hub lists
the nine old APIs as legacy, "available on the Pilot environment only"; **no retirement
date** appears in the migration guide, the API index or the changelog as of 2026-10-16.

**EBSI Core API v1.** One API replaces the nine services, under a per-node base:

| Environment | Base URL |
|---|---|
| pilot | `https://api-pilot.ebsi.<operator domain>/v1` |
| preprod | `https://api-preprod.ebsi.<operator domain>/v1` |
| prod | `https://api.ebsi.<operator domain>/v1` |

`<operator domain>` is the domain of a node operator, taken from the TNL. The reads
`openvc_ebsi` makes:

| Read | Legacy pilot lane (v5) | Core API v1 (under `/v1`) |
|---|---|---|
| DID document | `/did-registry/v5/identifiers/{did}` | `/did-registry/identifiers/{did}` |
| Issuer record | `/trusted-issuers-registry/v5/issuers/{did}` | `/issuers-registry/issuers/{did}` |
| Attribute list | `…/issuers/{did}/attributes` | the same suffix under `/issuers-registry` |
| One attribute | `…/attributes/{id}` | the same suffix under `/issuers-registry` |

What ADR-0009 found on Core v1 nodes: the sampled response bodies match the shapes
`openvc_ebsi` parses for v5, apart from one field the recorded v5 fixtures lack,
`parentAttributeId`; the list item `id` differs from `attribute.hash` in both attributes
sampled; the `self` and `links` URLs carry the *answering node's own host*. EBSI documents
errors as RFC 9457 Problem Details with a `type` of the form `urn:ebsi:problems:<slug>`, and a
limit of 20 requests per second per client IP.

**`openvc_ebsi` reads both layouts, selected together.** The default adapters are the v5 ones.
For a Core v1 node, pass the node's bare origin as `base` and the Core v1 adapters as `didr` and
`tir`, over a client whose allow-list holds that node's host (`"core-v1"`: `DidRegistryCoreV1` and
`TirCoreV1`; [Trust anchors](Trust) has the example). What a Core v1 node answers to a v5 path
was not measured (*to be measured*), and nothing should rely on mixing the two.

The TNL's `pilot` environment is **not** the legacy pilot. On 2026-10-16 the legacy DID
`did:ebsi:zZeKyEJfUTGwajhNyNX928z` answered 404 (`urn:ebsi:problems:identifier-not-found`) on both
TNL pilot nodes tried, while `api-pilot.ebsi.eu` answered 200 for it. They behave as different
ledgers, so the recorded fixtures say nothing about them.

## The three names today

`for_ebsi(environment)` seeds the allow-list from one fixed host per name, `legacy-pilot` by
default. As of 2026-10-16:

| Name | Host | What it is |
|---|---|---|
| `legacy-pilot` | `api-pilot.ebsi.eu` | The **legacy pilot lane** above, and the default. |
| `pilot` | `api-pilot.ebsi.eu` | The same host and lane as `legacy-pilot`, **deprecated since 1.37.0**: `for_ebsi("pilot")` warns (`DeprecationWarning`, naming `legacy-pilot`) and builds the same client. Not the TNL's `pilot` environment, and it will change meaning at the next MAJOR release (2.0, [#74](https://github.com/luisgf/openvc/issues/74)). |
| `conformance` | `api-conformance.ebsi.eu` | The name resolves, but no TCP connection completed within 12 s (curl exit 28). It is outside the TNL's scope. |
| `production` | `api.ebsi.eu` | **Not a node.** No HTTP response was obtained: of four addresses, two did not accept a connection in about 3 s and 6 s, and the one that answered presented a certificate for an Amazon Lightsail wildcard that does not cover `api.ebsi.eu`, so verification stops at the handshake (curl exit 60). Whether any address serves a certificate valid for the name is not established. |

Production nodes are `api.ebsi.<operator domain>` hosts taken from the TNL: 10 of them in list
version 4. The names stay as they are for now (an unknown name is `UnknownEbsiEnvironment`), by
the maintainer's decision of 2026-10-19 on
[#325](https://github.com/luisgf/openvc/issues/325): `pilot` is deprecated in favour of
`legacy-pilot`; `conformance` and `production` are kept, documented here and silent (no
warning, no refusal). The reasons are #325's reading, not part of the decision. EBSI now also
calls its Core API pilot "pilot", and the name will mean that ledger at the next MAJOR release,
so `pilot` has a replacement to point at. `for_ebsi` has no name to point `conformance` and
`production` at: the node-based client that would take its nodes from the verified list does
not exist yet (#324), and until it does the recipe below is how to reach a node. A request
through a client built from `production` or `conformance` is not known to complete today, as the
table says.

## Getting the nodes

The TNL is a short chain: one pinned key, and two documents signed with OpenPGP. It is served at
<https://tnl.ebsi.eu> and published in the public repository
<https://gitlab.com/europeum/public/trusted-nodes-list> (its README and `public/` directory):

```text
Europeum key-list key   (pinned out of band; the one thing a verifier trusts up front)
      | signs trusted-keys.json.sig
      v
trusted-keys.json       (version, threshold, the custodians' public keys)
      | the custodians sign tnl.json.sig
      v
tnl.json                (version, keysVersion, issued, expires, nodes per environment)
```

Five files make up the chain: `tnl.json`, `tnl.json.sig`, `trusted-keys.json`,
`trusted-keys.json.sig` and `keylist-key.asc`. ADR-0009's appendix downloads and
fingerprint-checks them like this:

```sh
for f in tnl.json tnl.json.sig trusted-keys.json trusted-keys.json.sig keylist-key.asc; do
  curl -fsS --proto =https -o "$f" "https://tnl.ebsi.eu/$f"
done
gpg --show-keys --with-fingerprint keylist-key.asc
```

The live chain on 2026-10-16: list version 4 with `keysVersion` 1, issued 2026-10-06T13:33:18Z
and expiring 2027-01-04T13:33:18Z (90.0 days); 10 prod, 12 preprod and 23 pilot nodes (45 URLs,
27 distinct operator domains); a key list at version 1 with `threshold` 2 and exactly two
custodians, so there is no redundancy. The files are served with `cache-control: public,
max-age=300, must-revalidate` and an `etag`.

**The one thing you pin.** The key-list key is a v4 ECDSA P-256 key created
2026-09-30T09:13:54Z. On 2026-10-16 its fingerprint read
`ACCC 82E5 FC89 02F1 1492 9481 747C B65C FB75 74F9`, and the hub repository, the TNL repository
and the file served at `tnl.ebsi.eu` all agreed on it. **Read that as a dated observation, not as
a value to copy from here.** All three channels are Europeum's: their agreement shows the
publisher is consistent, not that the key is genuine. An out-of-band confirmation from
Europeum would be stronger. Whether and how openvc itself pins the key is undecided
(ADR-0009, open question 2), and a wiki page is not a channel to trust a fingerprint from.
Never download the pinned key at verification time. The TNL README calls this key a stopgap
until Europeum's qualified electronic seal replaces it.

## What verifying it entails

The publisher's own rules (the README's "Verify the list", as ADR-0009 summarises them) are a
checklist. Fail closed on any item that does not hold.

- [ ] `trusted-keys.json` verifies against the pinned key-list key.
- [ ] A signature counts only if it is valid, made by an allowed key identified by its **primary**
  fingerprint, ECDSA with SHA-256, SHA-384 or SHA-512, over a **binary** document.
- [ ] **Any invalid signature rejects the file.** Signers that are not allowed are ignored. A key
  that signs twice counts once.
- [ ] At least `threshold` **distinct** custodians signed `tnl.json`.
- [ ] `tnl.json` validates against the JSON Schema the README prints.
- [ ] `expires` is in the future and at most 90 days after `issued`; `issued` is not in the
  future (the publisher allows 5 minutes of skew).
- [ ] `keysVersion` does not exceed the key list's `version`.
- [ ] `version` exceeds the last one you accepted; equal only if the bytes are identical (next
  section).
- [ ] Every node URL is a bare `https://` origin (no path, port or credentials) that starts with
  its environment's prefix (`https://api-pilot.ebsi.`, `https://api-preprod.ebsi.`,
  `https://api.ebsi.`) and appears once.
- [ ] Keep the last accepted list until its own `expires`; refresh about hourly with
  `If-None-Match`.
- [ ] Never download the pinned key at runtime.

**Method.** Follow the TNL README's `gpg` procedure, or use an OpenPGP library in your own
stack. Authenticate before you parse: read the custodians' key blocks only after the pinned key
has verified `trusted-keys.json`, and `tnl.json` only after the threshold is met. The only
command ADR-0009 gives is the fingerprint check above. A complete command sequence for the two
detached signatures is *to be measured* and is not reproduced here: run whatever you use
against the then-live list, and against tampered copies, before you rely on it. ADR-0009
reports that its (uncommitted) scratch verifier rejected each of these, and a verifier of
yours should too:

- a changed host name in `tnl.json`, one flipped bit, an appended newline;
- one flipped bit inside a signature's `s` value;
- a signature checked against the wrong key, and `tnl.json.sig` offered for `trusted-keys.json`;
- only one of the two custodian signatures (below the threshold).

It also found that the same signature presented twice counts as one signer.

## Persist what you accepted

A stateless verifier cannot protect itself from replay: an old list that was validly signed
still verifies, until its own `expires` (at most 90 days later). So persist, for the node list
**and** for the key list, the last accepted `(version, sha256)` pair, and apply one rule to
each:

| Candidate | Decision |
|---|---|
| `version` higher than the pair | accept, then store the new pair |
| `version` equal, same SHA-256 | accept (an hourly re-verification of the list you already hold) |
| `version` equal, different bytes | reject: rollback |
| `version` lower | reject: rollback |

The key list needs its own pair: `trusted-keys.json` carries no expiry, so a stale, validly
signed key list from before a custodian rotation could otherwise be replayed together with an old
custodian key. The key list's own `version` is what to compare, never the node list's
`keysVersion`, which the custodians sign. (As far as ADR-0009 could tell, the README rolls back
`tnl.json` only; treating the key list the same way is ADR-0009's reasoning, not a publisher
rule.) Store the pair only after the
whole chain has been accepted. Nothing can force a caller to store an honest value: starting
again from no stored pair is always possible, and then only a version floor bounds replay:
`verify_node_list` ships two (ADR-0009 D3), and it takes your stored pairs as required arguments.

## From a verified list to an explicit allow-list

`EbsiHttpClient(allowed_hosts=…)` takes host names, and it stays the primitive. Build the set
from a list you have **already verified**, with these rules:

- **One environment per client, never a union.** The three environments are different ledgers,
  and a pilot host answering a prod resolution is the mix-up the publisher's prefix rule exists
  to stop.
- **Host names only**: strip the `https://`. Re-check that each URL is a bare `https://` origin,
  ASCII, once in the list, with its environment's prefix.
- **Refuse a node URL with a port.** The client's guard admits an origin: `https` on a listed
  host at port 443 only, and no userinfo, so a request to `https://host:9200/…` or
  `https://user@host/…` is `HttpForbiddenHost` before any I/O. The allow-list still holds host
  *names*, so a listed `https://host:9200` stripped to `host` would silently become `host:443`.
  The publisher's rules forbid a port or credentials in a node URL, so a list that contains one
  fails the checklist above; refuse it rather than strip it.
- **Rebuild before the list's `expires`.** A client built by hand has no expiry bound and the
  library offers no grace past it; re-verifying is entirely your job.
- **Pass `DidEbsiResolver(..., base=…, didr=DidRegistryCoreV1(), tir=TirCoreV1())` per node.** The
  default base is `api-pilot.ebsi.eu`, the legacy lane, with the v5 adapters.

The snippet runs offline, on a literal sample (the hosts are examples). Its negatives come
first: a list it refuses never becomes a client, and a host outside the set, or another
environment's host, raises `HttpForbiddenHost` before any socket is opened. The positive path
only inspects the host set.

<!-- docs: needs=httpx -->
```python
import re
from datetime import datetime, timezone

from openvc_ebsi.http import EbsiHttpClient, HttpForbiddenHost

# The URL prefix the publisher requires for each environment's nodes.
PREFIX = {"pilot": "https://api-pilot.ebsi.", "preprod": "https://api-preprod.ebsi.",
          "prod": "https://api.ebsi."}
BARE_ORIGIN = re.compile(r"https://[a-z0-9.-]+")      # no port, path, userinfo; ASCII only


def allow_list(verified: dict, environment: str, *, now: datetime) -> frozenset[str]:
    """Host names of ONE environment of a list whose signatures, threshold, rollback and
    schema were already checked elsewhere. Anything unexpected is a ValueError, a list of
    the wrong shape included, so one `except ValueError` means "refuse this list"."""
    try:
        return _hosts(verified, environment, now)
    except (AttributeError, KeyError, TypeError) as exc:    # a missing key, a wrong type
        raise ValueError(f"malformed list ({type(exc).__name__})") from exc


def _hosts(verified: dict, environment: str, now: datetime) -> frozenset[str]:
    if environment not in PREFIX:
        raise ValueError(f"unknown environment {environment!r}")
    expires = datetime.fromisoformat(verified["expires"].replace("Z", "+00:00"))
    if now >= expires:
        raise ValueError("the list has expired: fetch and verify a newer one")
    nodes = verified["environments"].get(environment)
    if not nodes:
        raise ValueError(f"the list has no {environment!r} nodes")
    hosts = []
    for node in nodes:
        url = node["url"]
        if not (BARE_ORIGIN.fullmatch(url) and url.startswith(PREFIX[environment])):
            raise ValueError(f"not a bare https origin of {environment!r}: {url!r}")
        hosts.append(url.removeprefix("https://"))
    if len(set(hosts)) != len(hosts):
        raise ValueError("duplicate host")
    return frozenset(hosts)


def sample(**environments: list[str]) -> dict:
    """A literal stand-in for a verified tnl.json."""
    return {"version": 4, "expires": "2027-01-04T13:33:18Z", "environments": {
        env: [{"url": u, "country": "XX", "organisation": "Example"} for u in urls]
        for env, urls in environments.items()}}


NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
PROD = ["https://api.ebsi.node-a.example", "https://api.ebsi.node-b.example"]
PREPROD = ["https://api-preprod.ebsi.node-a.example"]


def reason(verified: dict, environment: str, now: datetime = NOW) -> str:
    """Why the list is refused (the test fails if it is not)."""
    try:
        allow_list(verified, environment, now=now)
    except ValueError as exc:
        return str(exc)
    raise AssertionError("the list was accepted")


# Negatives first. A list that is refused never becomes a client:
EXPIRES = "2027-01-04T13:33:18Z"
assert "malformed list" in reason({"version": 4}, "prod")                      # no expiry
assert "malformed list" in reason({"expires": EXPIRES}, "prod")                # no environments
assert "malformed list" in reason({"expires": "2027-01-04T13:33:18", "environments": {
    "prod": [{"url": PROD[0]}]}}, "prod")                                      # naive expiry
assert "malformed list" in reason({"expires": EXPIRES, "environments": {
    "prod": [{"country": "XX"}]}}, "prod")                                     # node without url
assert "malformed list" in reason({"expires": EXPIRES, "environments": {
    "prod": [{"url": 7}]}}, "prod")                                            # url not a string
assert "malformed list" in reason({"expires": EXPIRES, "environments": []}, "prod")  # not a map
assert "bare https origin" in reason(sample(prod=["https://api.ebsi.node-a.example/v1"]), "prod")
assert "bare https origin" in reason(sample(prod=["https://api.ebsi.node-a.example:9200"]), "prod")
assert "bare https origin" in reason(sample(prod=["https://user@api.ebsi.node-a.example"]), "prod")
assert "bare https origin" in reason(sample(prod=["http://api.ebsi.node-a.example"]), "prod")
assert "bare https origin" in reason(sample(prod=["https://api.ebsi.n\u00f6de.example"]), "prod")
assert "bare https origin" in reason(sample(prod=PREPROD), "prod")    # another environment
assert "duplicate host" in reason(sample(prod=[PROD[0], PROD[0]]), "prod")
assert "no 'preprod' nodes" in reason(sample(prod=PROD), "preprod")  # absent from the list
assert "expired" in reason(sample(prod=PROD), "prod",
                           now=datetime(2027, 1, 4, 13, 33, 18, tzinfo=timezone.utc))

# One environment, one client. A host outside the set, or another environment's host,
# is refused by the guard before any socket is opened:
verified = sample(prod=PROD, preprod=PREPROD)
hosts = allow_list(verified, "prod", now=NOW)
with EbsiHttpClient(allowed_hosts=set(hosts)) as http:
    for url in ("https://api.ebsi.node-c.example/v1/alive",          # not listed
                "https://api-preprod.ebsi.node-a.example/v1/alive"):  # listed, but preprod
        try:
            http.get_json(url)
        except HttpForbiddenHost as exc:
            assert type(exc) is HttpForbiddenHost
        else:
            raise AssertionError(f"{url} was not refused")

# The positive path only inspects the set; it makes no request.
assert hosts == {"api.ebsi.node-a.example", "api.ebsi.node-b.example"}
```

## What a signed list does not authenticate

The list authenticates the **operator**, not the **data**.

- Registry responses are unsigned JSON from whichever node answers. A dishonest listed node can
  serve another key for a DID, or forged accreditations, and `openvc_ebsi` would verify them.
- The mitigation that exists is comparing the trust-critical reads across nodes. That is a policy
  with a cost (twice the requests, against EBSI's 20 requests per second per IP), and it belongs
  to you. This page prescribes neither a pattern nor a helper, and whether a 404 on one node is
  authoritative is an open question (ADR-0009, open question 5).
- The chain's real root is the single key-list key. With it an attacker can substitute
  `trusted-keys.json` (the custodians and the threshold) and then sign any list; the two-custodian
  threshold only protects against compromise of the custodians.
- DNS or certificate compromise of one listed host is not defended. The opt-in
  `address_guard=AddressGuard()` refuses a listed name that resolves to a non-public address and
  connects to the validated address (off by default, refused behind an environment proxy); it
  does not stop an attacker who holds a valid certificate for a public address.
- A node that is revoked between two list versions stays trusted until you next refresh. The
  outside bound is the list's `expires` (at most 90 days after `issued`), but a hand-built
  allow-list does not stop at `expires` by itself: the bound is the rebuild interval you enforce.
- Nothing is known about operators' availability: no SLA has been found.

## Do not match patterns

`api.ebsi.*` authenticates nothing. The part after `ebsi.` is whatever domain the operator owns,
so `api.ebsi.attacker.example` needs only a domain the attacker controls, a public certificate
for it (domain validation) and a registry response. A suffix rule fails the other way: none of the
45 node hosts in list version 4 is under `ebsi.eu`, and the 27 operator domains include
second-level and third-party zones (one pilot node is under `trafficmanager.net`, a shared cloud
zone whose takeover profile differs from an operator-owned domain: an inference, not tested).
The publisher's prefix check is useful only *after* a list has been authenticated, where it
stops a node from posing as another environment.

## Known limits on Core v1 today

As of 2026-10-16:

- **Recursive trust needs an opt-in.** The prod and preprod RootTAO accreditations are signed
  `ES256K`. `VcJwtProofSuite.verify` on the preprod one raised `UnsupportedAlgorithm`, because
  the default JOSE allow-list rejects it, so with a default suite `verify_ebsi_badge(...,
  trust_anchors=…)` and `verify_trust_chain` cannot verify a Core v1 root. The maintainer accepted
  an explicit opt-in on 2026-10-16 (ADR-0009, open question 3), and it is implemented
  ([#323](https://github.com/luisgf/openvc/issues/323)): pass `VcJwtProofSuite(allow_es256k=True)`
  as the `proof_suite`. It is verification only, VC-JWT only, and leaves the default list alone;
  the recorded preprod RootTAO verifies with it ([Keys & HSM](Keys-and-HSM#es256k-ebsi-interop-opt-in)).
  One suite serves the leaf badge and every hop, so an opted-in suite also accepts an
  `ES256K`-signed leaf badge. Single-level trust reads the accreditation without verifying its
  signature, with the registry as the anchor, and was never blocked by this: ADR-0009 fed recorded
  v1 bodies, offline, through the unmodified v5 parsers and got a correct issuer record.
- **Prod holds almost nothing.** One seeded issuer, `did:ebsi:z262SoSjWAqmXpaGmzqGnJoc`, whose
  DID document has an empty `verificationMethod`, so recursive trust could not succeed on prod
  even with the `ES256K` opt-in. Preprod holds 244 issuers with real keys. The content will
  change when operators onboard.
- **Hosts inside accreditations are in no environment.** `credentialSchema.id` names
  `api-prod.ebsi.eu` and `api-test.ebsi.eu`. `openvc_ebsi` does not follow them, and a future
  schema fetch must not add them to the node allow-list.
- **A node's front can refuse a client by User-Agent.** `api.ebsi.stsisp.ro` answered curl's
  default User-Agent with a 403 HTML "Web Application Firewall" page (not Problem Details), and a
  client named `openvc-core/<version>` with 200 JSON. If you override `user_agent`, a 403 is a
  reason to try another node, not to abort, and its body is not a Problem Details document.
- **No SLA, pricing or onboarding document** has been found for automated readers.

## What to watch

- **2026-10-22**: the EBSI Ecosystem Roadshow & Business Launch in Bucharest, announced on the
  ebsi.eu home page. That is the organiser's own page with no second source, and it announces an
  event, not that a production API goes live. Look for SLA, pricing and access terms for automated
  readers, a change to the 20 requests per second limit, and a working certificate for
  `api.ebsi.eu`.
- **2027-01-04**: list version 4 expires. Expect a new version before then. If none appears,
  every strict client fails closed.
- **The hub changelog** (<https://hub.ebsi.eu/api/changelog>) for Core API v1 amendments and a
  legacy retirement date, and the [migration guide](https://hub.ebsi.eu/api/migration-guide).
- **The TNL repository and `trusted-keys.json`**: a new key-list `version`, a change of threshold
  or custodians, and the switch from the key-list key to Europeum's qualified electronic seal.
- **Prod content**: the single seeded issuer, and `ES256K` in the roots.
