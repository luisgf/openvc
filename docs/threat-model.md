# Threat model

openvc verifies Verifiable Credentials, handles signing keys, and dereferences
issuer-named URLs over the network. This page states what it defends, against whom,
and how — the reference an auditor (or an integrator) starts from. The
per-control hardening notes are in
[SECURITY.md](https://github.com/luisgf/openvc/blob/main/SECURITY.md).

## Assets

- **The verification decision.** The accept/reject output of `verify_credential`
  (and `verify_ebsi_badge`) is the asset everything else protects: a *wrong accept*
  (a forged/tampered/expired/revoked credential accepted) is the primary harm.
- **Signing keys.** Private key material. openvc never requires it in-process on the
  signing path — signing goes through the `SigningKey` protocol, so an HSM/Vault/KMS
  backend keeps keys out of the process.
- **Trust anchors.** The roots a verifier trusts: X.509 `x5c` trust anchors, the
  EBSI RootTAO, the DID documents a resolver returns. Compromise of an anchor is
  out of scope (it is the operator's root of trust) but openvc must not *widen* it.

## Trust boundaries

Untrusted input crosses into openvc at:

1. **The credential itself** — fully attacker-controlled bytes (a JWS/SD-JWT string
   or a JSON document). Every field is untrusted until the signature verifies.
2. **Network dereferences** — `did:web`, `/.well-known/jwt-vc-issuer`, status-list
   and `credentialSchema` URLs. The *issuer* names these URLs and (for status/schema)
   controls the bytes returned. All of these are attacker-influenced.
3. **The `SigningKey` / key-agreement backend** — an out-of-process boundary (HSM,
   Vault, KMS). openvc trusts it to sign/decrypt but not to hold key material for it.
4. **Injected resolvers** — `resolver`, `resolve_status_list*`,
   `resolve_credential_schema`, `*_fetch`. openvc's guarantees hold only for what
   these return; a custom resolver that skips verification or the SSRF guard opts
   out of the corresponding control (hence the blessed defaults in `openvc.resolvers`).

## Attacker capabilities & controls

| Attacker capability | Threat | Control |
|---|---|---|
| Present a forged / tampered credential | Wrong accept | Signature verification through the matching suite; the `{ES256, EdDSA}` **allow-list runs *before* any crypto** (rejects `alg:none`, RS\*, HS\* — alg-confusion defence); JWS is R‖S, never DER |
| Name an arbitrary issuer but sign with own key | Impersonation | **Issuer binding** — a Data Integrity proof's `verificationMethod` must be controlled by the credential's `issuer` DID; VC-JWT reconciles the JWT envelope with the embedded credential; x5c binds the leaf SAN to `iss` |
| Serve a malicious document at a fetched URL | **SSRF** (reach internal hosts / cloud metadata) | `openvc.fetch`: https-only, blocks private/loopback/link-local/reserved/multicast IPs, refuses redirects, **pins the connection to the validated IP** (closes DNS-rebinding). Status/schema fetches use the same guard via the blessed `openvc.resolvers` defaults |
| Ship a tiny highly-compressible status list | **Decompression bomb** (OOM DoS) | Status decode caps the *decompressed* output at 16 MiB and fails closed (`StatusListError`), reading incrementally so a bomb is never materialised |
| Point `credentialSchema` at a schema with a catastrophic `pattern` | **ReDoS** (CPU DoS) | Schema validation is **opt-in**; remote `$ref` is off (no SSRF via `$ref`). Residual `pattern`-ReDoS is a documented limitation (mitigation tracked) — point the schema resolver at trusted hosts |
| Swap / replay a status list or presentation | Stale-status / replay accept | Status-list token `sub` must equal the fetched URI (anti-swap); presentations bind `aud` + one-time `nonce`/`challenge`; a fetched status list is **verified** before it is trusted |
| Backdate / post-date validity | Expired/not-yet-valid accept | Temporal checks on `validFrom`/`validUntil` (+ VCDM 1.1 aliases) and proof `expires`; a **present-but-unparseable** timestamp fails **closed**, never silently skipped |
| Withhold a selectively-disclosed status/schema | Skip a fail-closed gate | Documented caveat: an issuer that needs status/schema enforced must make the pointer **non-selectively-disclosable** (mandatory for ecdsa-sd, outside `disclosable` for SD-JWT) |
| MITM a fetch | Tamper in transit | TLS with certificate validation and SNI on the pinned connection |

## Design posture

- **Fail closed.** Ambiguity, an unresolvable key, a malformed timestamp, an
  unrecognised status/schema shape, or a missing opted-in resolver all *reject*
  rather than accept.
- **Least authority on the network.** Every dereference is https-only and
  SSRF-guarded by default; nothing is fetched from an allow-list openvc did not vet.
- **HSM-friendly.** Key material need never enter the process.

## Out of scope

- Compromise of a trusted anchor, of the host, or of the `SigningKey` backend.
- Availability of remote issuers / status lists (openvc bounds *its own* resource
  use — response size, decompressed size, recursion — but cannot guarantee a third
  party is reachable).
- Anything an **injected** resolver does after openvc hands it a URL, if the caller
  supplies a custom one instead of the guarded default.
- Side-channels in the underlying `cryptography` / `pyjwt` primitives.
