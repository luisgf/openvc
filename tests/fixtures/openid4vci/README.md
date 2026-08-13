# OpenID4VCI vectors — the spec's own examples and real EUDI artifacts

Pins for `openvc.openid4vci` against material **we did not write** (issue #147,
[ADR-0007](../../../docs/adr/ADR-0007-oid4vci-issuer-side.md) D10). The key-proof
verifier is the highest-consequence path added in the 1.22 cycle — a wrong-accept there
hands an attacker a credential bound to a key they do not control — and it shipped
pinned entirely by vectors this repo minted itself.
`tests/fixtures/trustlist/real/README.md` is the standing evidence that self-made
fixtures hide total-failure bugs.

Consumed by `tests/test_openid4vci_vectors.py`. Offline and deterministic: the one
fixture carrying a signature is verified with the clock **frozen** to its own `iat`, the
technique the EUDI PID fixtures already use, so nothing here rots.

## `spec/` — OpenID4VCI 1.0 examples

Transcribed from [OpenID for Verifiable Credential Issuance 1.0, Final
(2025-09-16)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
retrieved 2026-07-27. Each file carries its own `_provenance` member naming section,
retrieval date and source; the payload sits under `request` (a §8.2 Credential Request
body) or `proofs` (an App. F.1 `proofs` object) so the parse target stays clean of it.
The spec wraps long base64url strings across lines for typesetting; the wrapping is
undone, the same treatment as `interop/rfc9901-a3-sd-jwt-vc.txt`.

| file | section | what it pins |
|---|---|---|
| `proof-f.1-jwt.json` | App. F.1, `jwt` Proof Type | The **only signed** vector here, and a third-party one: a complete ES256 compact JWS over its own embedded `jwk`, `aud` `https://credential-issuer.example.com`, `iat` 1701960444 (2023-12-07), nonce `LarRGSbmUPYtRYO6BQ4yn8`. It verifies end-to-end, so a change to the `typ` pin, the key↔`alg` binding, the signing-input assembly or the `aud`/`iat`/nonce checks breaks it. F.1's second block is this same token decoded, which is what makes the header/payload assertions checkable. |
| `request-8.2-mdl-jwt-proof.json` | §8.2, first example | `credential_configuration_id` + a single-element `jwt` array — the minimal §8.2 shape. The proof value is **truncated in the spec** to a bare header, so it pins the request shape and then a clean `MalformedToken`, not a signature. |
| `request-8.2-degree-two-jwt-proofs.json` | §8.2, second example | `credential_identifier` (the other, mutually exclusive selector) and a **two**-element batch. Default `batch_size` is 1, so this is rejected until the caller opts in — the fail-closed default an issuer that publishes no `batch_credential_issuance` needs. |
| `key-attestation-app-d.json` | App. D + the `jwt` Proof Type's attested example | The App. D key attestation and the proof whose `kid: "0"` indexes its `attested_keys`. Both are printed **decoded** in the spec and the proof's attestation is a placeholder, so what is third-party is the *shape* — member names, types, and that a `kid` here is a position, under no normative rule — and the test re-encodes them. It pins that `peek_key_attestation` reads every App. D member without judging `typ`, `exp` or the truncated `x5c`, and that the attested-key binding accepts the spec's own pairing and refuses a stranger's key. |
| `request-8.2-degree-di-vp-proof.json` | §8.2, third example | A `di_vp` proof, whose elements are JSON **objects** rather than strings. ADR-0007 keeps `di_vp` out; the pin is that it is refused as `UnsupportedProofType` — never ignored, and never mislabelled as a malformed request. This vector is what found that mislabelling. |
| `offer-4.1.1-pre-authorized.json` | §4.1.1 Credential Offer | The pre-authorized-code example: two `credential_configuration_ids`, the URN grant with its `tx_code` block. Pins that `parse_credential_offer` keeps the whole grant object and reads both ids in order. |
| `offer-4.1.1-authorization-code.json` | §4.1.2 by-reference response body | The authorization-code example, `issuer_state` truncated in the spec and carried as the opaque string it is. |
| `issuer-metadata-11.2.3.json` | §11.2.3 Credential Issuer Metadata | The spec's own metadata document: every endpoint member, `authorization_servers`, `batch_credential_issuance.batch_size` 10, and the extension points (`display`, both encryption blocks, per-configuration shapes) a parser must pass through untouched. |

## `real/` — recorded from the EU reference issuer

Live capture from `https://issuer.eudiw.dev`, the deployment of
[`eudi-srv-web-issuing-eudiw-py`](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py),
on **2026-07-27** (`Date: Mon, 27 Jul 2026 09:32:58 GMT`). Vendored byte-for-byte — do
not edit. Provenance lives in this table rather than inside the files, because an
artifact recorded to prove "this is what the ecosystem actually sends" stops being that
the moment we add a member to it; `tests/test_openid4vci_vectors.py` re-checks each
`sha256` so the claim is enforced, not decorative.

The deployment advertises no application version (`Server: nginx/1.18.0`, no version in
its metadata), so the retrieval date and these digests are the version.

| file | source | sha256 |
|---|---|---|
| `eudiw-issuer-metadata.json` | `GET https://issuer.eudiw.dev/.well-known/openid-credential-issuer` | `d898a8eba64be7eb28820a1b6d72d5c8d5e9868ee498c625e2754db5864bcc70` |
| `eudiw-offer-pid-sd-jwt.uri` | Credential Offer for `eu.europa.ec.eudi.pid_vc_sd_jwt`, authorization-code grant, as the issuer's own QR page emits it | `72cb82fd88aedb4de885a15835efcfd2ab08fbe8cf45a18c41c796b3d7947483` |
| `eudiw-offer-pid-mdl.uri` | Same, two credentials (`pid_vc_sd_jwt` + `mdl_mdoc`) and the `openid-credential-offer://` scheme | `cc8dc0a2745f2a75e99e005a72a4c86bef063eb2aba074b65e1ead332e9737af` |

Both offers are the **deep-link form** a wallet actually receives —
`<scheme>://credential_offer?credential_offer=<percent-encoded JSON>` — not a
pre-decoded object, so they pin the transport too. Their `issuer_state` values are
one-time demo grants, long expired; nothing here is a live credential.

91 KB of Issuer Metadata is the point of it: 27 credential configurations across mdoc
and SD-JWT VC, `batch_credential_issuance.batch_size` 100, a `nonce_endpoint`,
credential request *and* response encryption blocks with published JWKS, and per-config
`proof_types_supported` declaring both `jwt` and `attestation` with
`key_attestations_required`. That is the shape the #142 parsers have to survive, and
none of it is what we would have invented.

## What is deliberately still missing

**Key-proof JWTs captured from a real wallet.** The proofs here are the spec's own
example and self-made ones; nothing in this directory is a proof a shipping wallet
produced. Getting one needs a live Credential Endpoint for a wallet to POST to, which
this library — by ADR-0007 D1 — does not have. Issue #147 records the source: a
downstream Django issuer built on the ADR-0007 consumer contract will run the EUDI
reference wallet against its own endpoint, and the request bodies from that run come
back here with provenance. Until then this gap is stated, not papered over.

**A key attestation from a real wallet provider**, for the same reason and with sharper
consequences: `key-attestation-app-d.json` is the spec's shape re-encoded here, and the
App. D binding check (issue #150) is on by default, so the ecosystem form it governs is
pinned only by material this repo shaped. The recorded EUDI metadata advertises
`key_attestations_required` on all 27 configurations, which is exactly how likely it is
that a real one looks different from the example in some way that matters. Same source
as above closes it.

Also absent: a pre-authorized-code offer. The reference issuer only mints one after a
form of synthetic personal data is submitted to it, which is not a trade this repo needs
to make for a shape it can read off §4.1.1.
