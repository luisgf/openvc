# VC-API conformance shim (test-only)

`vc_api_shim.py` exposes the [VC-API](https://w3c-ccg.github.io/vc-api/) HTTP endpoints
the official **W3C Verifiable Credentials test suites** drive, backed by openvc's Data
Integrity suites. Registering openvc through
[`w3c/vc-test-suite-implementations`](https://github.com/w3c/vc-test-suite-implementations)
puts it into the **public implementation reports** — third-party conformance evidence a
single-maintainer library cannot get any other way (the repo's golden fixtures prove drift
*to us*; the reports prove conformance *to everyone else*).

This is **not** a shipped API surface. It lives under `tests/`, adds **no runtime
dependency** (stdlib `http.server`), holds ephemeral per-process keys, and does no
auth / TLS / persistence. `tests/test_vc_api_shim.py` keeps it working in CI.

## Endpoints

| Method + path | Body | Result |
|---|---|---|
| `POST /credentials/issue` | `{credential, options:{cryptosuite}}` | `201 {verifiableCredential}` |
| `POST /credentials/verify` | `{verifiableCredential, options}` | `200`/`400 {checks,warnings,errors}` |
| `POST /presentations/verify` | `{verifiablePresentation, options:{challenge,domain}}` | `200`/`400 {…}` |

Cryptosuites: `eddsa-rdfc-2022`, `eddsa-jcs-2022`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`.
The issuer issues as its own `did:key` (so every proof's `verificationMethod` resolves
offline). The ECDSA curve defaults to P-256; `OPENVC_SHIM_ECDSA_CURVE=P-384` selects the
P-384 track.

## Run it

```bash
pip install -e ".[all]"                 # the RDF cryptosuites need pyld
python tests/tools/vc_api_shim.py --port 8080
# -> openvc VC-API shim on http://127.0.0.1:8080  (ecdsa curve: P-256)
```

## Run the official W3C suites against it

The suites are Node/Mocha harnesses that read a local implementation config and POST to
the endpoints above. Sketch (see each suite's README for the current invocation):

```bash
git clone https://github.com/w3c/vc-di-eddsa-test-suite && cd vc-di-eddsa-test-suite
npm i
# point its .localImplementationsConfig at openvc-implementation.json (below), then:
npm test
```

Run the four named suites — `vc-data-model-2.0`, `vc-di-eddsa`, `vc-di-ecdsa`,
`bitstring-status-list` — before a release or on a schedule, and link the generated
reports from the top-level `README.md`.

## Registration

`openvc-implementation.json` is the manifest submitted (as a PR) to
`w3c/vc-test-suite-implementations`. Reconcile its `tags` with the tag names the target
suite version expects, and point `endpoint` at a reachable shim (localhost for a local
run, a hosted instance for the published reports). The `did:key` issuer keys are ephemeral,
so a published run should pin a stable key if a suite requires issuer continuity.
