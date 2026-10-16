# tests/fixtures/ebsi

Recorded EBSI responses. The `tir_v5_*` and `didr_v5_*` files are pilot registry bodies; this
note covers `tnl_response_headers.json` (#320).

## tnl_response_headers.json

One live measurement of `https://tnl.ebsi.eu/` (the Trusted Nodes List host, ADR-0009), taken
on 2026-10-16: **8 GETs** (the four files unconditionally, then the four again with the `ETag`
just received as `If-None-Match`), through `openvc_ebsi.http.for_tnl()` with its own default
`User-Agent` (`openvc-core/1.36.0`), `Accept: */*`, `Accept-Encoding: identity`, certificate
verification on, redirects not followed, one attempt per request, and no credentials or cookies.

It stores, per request: the status, the headers `ETag`, `Cache-Control`, `Content-Type`,
`Content-Length`, `Content-Encoding` and `Vary` when present, the names of all response
headers, whether `Set-Cookie` was present, and, for a 200, the body length and SHA-256. It does
**not** store the bodies: those are the signed documents the verifier of #319 takes as its
fixtures. `tests/test_ebsi_http_bytes.py` replays these header sets through `MockTransport`
(with zero bytes of the recorded length as the body) and pins the four answers the recording
settled:

1. the client's own `User-Agent` is served a 200 on all four files;
2. `Accept-Encoding: identity` yields no `Content-Encoding`;
3. every file carries an `ETag`, and it is strong (quoted, no `W/`);
4. `If-None-Match` with that `ETag` yields a 304 with no content (no `Content-Length`), on all
   four.

Two observations, not contracts: in this recording each `ETag` is the quoted SHA-256 of the
body it came with, and the server sent no `Set-Cookie`. The client treats an `ETag` as opaque
and does not rely on either.

To re-record, make the same eight requests and no more; this host is not ours.
