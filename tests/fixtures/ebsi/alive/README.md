# EBSI Core API v1 `/v1/alive` fixtures (recorded)

Real answers of `GET /v1/alive` from two EBSI Core API v1 **production** nodes, recorded once on
2026-10-19 for [#324](https://github.com/luisgf/openvc/issues/324) (design:
[ADR-0009](../../../../docs/adr/ADR-0009-ebsi-core-api-v1-and-node-trust.md)). They are the drift
alarm for the health check of `openvc_ebsi.node_client` (`EbsiNodeClient.check_health`): what a
healthy node's body looks like, byte for byte. Nothing here is edited; `MANIFEST.json` lists the
request URL, status, media type, node, retrieval time, headers sent, size and SHA-256 of each file,
and `tests/test_ebsi_node_client.py` hashes every file against it.

| Node | Body | Head |
|---|---|---|
| `api.ebsi.iti.gr` | `api.ebsi.iti.gr.body` | `api.ebsi.iti.gr.headers` |
| `api.ebsi.edelivery.lt` | `api.ebsi.edelivery.lt.body` | `api.ebsi.edelivery.lt.headers` |

## How they were recorded

Plain read-only GETs: no credentials, no cookies sent, no redirects followed, TLS verification on,
`curl --proto =https`, about one second apart, with the headers `EbsiHttpClient` itself sends
(`User-Agent: openvc-core/1.36.0`, `Accept: application/json, application/did+ld+json, */*;q=0.1`;
ADR-0009 measured one node's firewall refusing curl's default User-Agent). **Three requests in
all**, to `api.ebsi.iti.gr`, `api.ebsi.edelivery.lt` and `api-preprod.ebsi.grnet.gr`; the response
heads are the files curl's `-D` wrote (status line and header lines, CRLF), kept whole because the
health check must not depend on any of them. The recorder was a scratch script and is not part of
the repository.

## What the recording showed (and the tests pin)

- Both nodes answered **200**, `Content-Type: application/json; charset=utf-8`, with the same
  body: `{"health_global":1}`, **19 bytes** (a JSON object with the integer `1`, no whitespace, no
  trailing newline). SHA-256 `f2f79b0c...` for both.
- **No cache validators** on either answer: no `Cache-Control`, `ETag` or `Last-Modified`. The hub
  documents that the node caches the health value for up to five minutes; that is the node's own
  caching, not something the response says.
- `api.ebsi.edelivery.lt` sets a **`SRV_ID` cookie** (`path=/`), the load-balancer affinity cookie
  ADR-0009 saw on the two `edelivery.lt` hosts; `api.ebsi.iti.gr` sets none. The client keeps no
  cookie jar (#317), so it is dropped.
- Both heads carry a long set of security headers (`Content-Security-Policy`,
  `Strict-Transport-Security`, ...) that mean nothing for a JSON read; the node's header casing
  differs between the two (`Access-Control-Allow-Origin` against `access-control-allow-origin`).

## Not recorded

- **The unhealthy answer.** The hub documents `{"health_global":0}` with status **503**, but no
  node was seen answering it, so that body is a **synthetic** input in the tests, labelled so. It is
  not vendored here and must not be mistaken for a measurement.
- **`api-preprod.ebsi.grnet.gr`** was asked too, once, and **no connection completed within 20 s**
  (curl exit 28, `Connection timed out`). It was not retried (the request budget was three), so it
  is one observation of a node that did not answer, not a finding about that node.
- **A firewall's 403 page** (ADR-0009: `api.ebsi.stsisp.ro`, 35 059 bytes of third-party HTML) is
  not vendored. A synthetic stand-in in the tests carries the measured facts (403, `text/html`,
  35 059 bytes), and says it is synthetic.
