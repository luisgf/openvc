# Security Policy

`openvc` is a security library — it verifies Verifiable Credentials, handles
signing keys, and resolves DIDs over the network. Vulnerabilities are taken
seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Report privately:

- Email **luisgf@luisgf.es** (you may encrypt to the maintainer's published key), or
- Use **GitHub Security Advisories** ("Report a vulnerability") on the repository.

Include a description, affected version(s), and a reproduction if possible. You
can expect an acknowledgement within a few days and coordination on a fix and
disclosure timeline.

## Supported versions

`openvc` is pre-1.0; only the latest released `0.x` version receives security
fixes. Pin a version and watch releases.

## Scope & hardening notes

Areas most relevant to security, and how the library is designed to fail closed:

- **Signature verification.** The VC-JWT suite pins an algorithm allow-list
  (`ES256`, `EdDSA`) *before* any crypto runs — `alg: none`, RS\*, HS\* are
  rejected (alg-confusion defence) — and reconciles the JWT envelope with the
  embedded credential. The Data Integrity suite verifies over the RDF canonical
  form.
- **SSRF.** The EBSI client enforces an https-only host allow-list. The separate
  `did:web` fetch (`openvc.fetch`) is https-only, refuses redirects, blocks
  private/loopback/link-local/reserved/multicast addresses, and pins the
  connection to the validated IP (closing the DNS-rebinding TOCTOU window).
- **JSON-LD contexts** for Data Integrity are served from a bundled offline
  allow-list; unlisted contexts fail closed rather than being fetched.
- **Private keys** sign through the `SigningKey` protocol, so an HSM/Vault backend
  can keep key material out of the process.
- **Resource bounds.** `openvc.fetch` caps a response at 1 MiB, and status-list
  decode caps the *decompressed* bitstring at 16 MiB, failing closed with
  `StatusListError` — a gzip/zlib compression bomb in an issuer-controlled
  `encodedList` / `lst` cannot inflate to an OOM. **Caveat:** status-list and
  `credentialSchema` fetches use a **caller-injected** resolver, so the
  `openvc.fetch` SSRF guard applies only if you pass it. Use the blessed defaults in
  `openvc.resolvers` (`default_status_list_resolver`,
  `default_status_list_token_resolver`, `default_credential_schema_resolver`) — they
  fetch through the guarded https fetch and, for status, verify the fetched list
  before trusting it. A custom resolver deliberately opts out of that guard.

For the full assets / trust-boundaries / attacker-capabilities picture, see the
[threat model](https://github.com/luisgf/openvc/wiki/Security-Model). The
code-cited auditor annex — per-parser attack-surface tables, the fail-closed
invariants catalog, the residual-risk register, and the fuzz-coverage / review
history — is the [external-audit pack](https://github.com/luisgf/openvc/tree/main/docs/audit).

If you believe any of these controls can be bypassed, that is exactly the kind of
report we want.
