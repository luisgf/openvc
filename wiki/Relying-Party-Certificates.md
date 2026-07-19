# Relying-party certificates (EUDI WRPAC + WRPRC)

Under CIR (EU) 2025/848 every EUDI wallet **relying party** carries a **Wallet-Relying
Party Access Certificate (WRPAC)** — an X.509 certificate (ETSI TS 119 411-8) that
authenticates *who is asking*: the relying party's EU-wide entity identifier, its
service identifier and trade name, rooted in the **Access Certificate Authority (ACA)**
trust anchors a Member State notifies. `openvc.rp_cert` reads that certificate over the
same `cryptography` X.509 machinery as [issuer `x5c`](Resolving-Issuer-Keys), with the
same fail-closed posture, and hands you a typed object to gate on.

Two entry points mirror the library's trusted / untrusted split:

- `parse_rp_access_certificate(cert)` — read the attributes **without** establishing
  trust (UNTRUSTED, like the `peek_*` helpers). For inspection only.
- `verify_rp_access_certificate(cert, *, trust_anchors, …)` — path-validate the chain
  to the ACA anchors **first**, then parse. The result is safe to act on.

<!-- docs: no-run -->
```python
from openvc.rp_cert import verify_rp_access_certificate

# aca_roots: a list of cryptography x509.Certificate ACA roots (from your trusted list)
rp = verify_rp_access_certificate(
    wrpac_der,                       # DER/PEM bytes, a base64 string, or an x509.Certificate
    trust_anchors=aca_roots,
    required_eku="0.4.0.19411.8.1",  # optionally require the EUDI relying-party EKU OID
)
print(rp.entity_identifier)          # EU-wide id (subject organizationIdentifier)
print(rp.trade_name)                 # human-readable name (subject commonName)
print(rp.registration_records)       # Subject Information Access URLs -> the registration record
print(rp.extended_key_usages, rp.certificate_policies)
```

`verify_rp_access_certificate` enforces signatures, the validity window, and
`basicConstraints` (a non-CA certificate cannot be smuggled in as an intermediate);
only the TLS-specific EKU requirement is relaxed, since a WRPAC is an e-seal/signature
certificate, not a TLS server certificate. A malformed certificate, a chain that does
not root in your anchors, or a missing `required_eku` raises `RpCertError` (an
`OpenvcError`). openvc ships no root store — the ACA anchors are yours.

The module does **not** hardcode which EKU or certificate-policy OID the EUDI profile
mandates (that value is still settling); it surfaces the parsed sets so you gate on
them with `required_eku` or by inspecting the returned object.

## The registration certificate (WRPRC)

The WRPAC answers *“who is asking?”*. The **registration certificate** — WRPRC, CIR (EU)
2025/848 Art. 8, *optional per Member State* — answers the other half: **“were they
registered to ask for this?”** It carries the relying party’s registered **entitlements**
and the credentials and attributes it may request.

A WRPRC is **not** X.509. ETSI TS 119 475 V1.2.1 clause 5.2 profiles it as a signed
**JWT** (`typ: rc-wrp+jwt`) or **CWT** (`typ: rc-wrp+cwt`), so `openvc.rp_registration`
reads it over the JOSE lane and the CBOR/COSE codec respectively, anchoring the signer’s
`x5c` / `x5chain` chain in **your** registrar roots. Same trusted/untrusted split:

<!-- docs: no-run -->
```python
from openvc.rp_registration import (
    check_matches_access_certificate,
    check_request_within_registration,
    verify_rp_registration_certificate,
)

reg = verify_rp_registration_certificate(
    wrprc_jwt,                       # a compact-JWS str, or COSE_Sign1 bytes for the CWT form
    trust_anchors=registrar_roots,   # the registration-CA roots you trust
)
print(reg.subject_identifier)        # `sub` — the EN 319 412-1 semantic identifier
print(reg.entitlements)              # https://uri.etsi.org/19475/Entitlement/...
print(reg.credentials)               # what it may request, per format

# 1. this registration really describes the party the WRPAC authenticated
check_matches_access_certificate(reg, rp)          # rp from verify_rp_access_certificate
# 2. ...and the request stays inside the registered scope
check_request_within_registration(reg, dcql_query)
```

`parse_rp_registration_certificate(token)` is the UNTRUSTED counterpart — it enforces the
signed-header profile (`typ`, the `{ES256, ES384, EdDSA, Ed25519}` allow-list *before* any
crypto, a fail-closed `crit`) but checks no signature and validates no chain.

### The two cross-checks are the point

Verifying the signature only proves a registrar signed *something*. The authorization
decision needs both cross-checks, and both fail closed:

- `check_matches_access_certificate` binds the WRPRC’s `sub` to the WRPAC’s
  `entity_identifier` (GEN-5.1.1-04). Without it, an attacker pairs their own valid WRPAC
  with **someone else’s** valid WRPRC and inherits that party’s scope. An identifier
  absent on either side is a failure, never a match.
- `check_request_within_registration` requires every DCQL credential query to match a
  registered `format` whose `meta` covers the requested one, and every requested claim
  `path` to fall inside the registered paths. A registered container (`["address"]`)
  covers its members (`["address","locality"]`); a request naming *no* claims asks for
  everything and is refused against an enumerated registration.

### Where the specification is thinner than it looks

Three things are worth knowing, because each is a place a naïve reading goes wrong:

- **One WRPRC = one intended use.** TS5’s data model nests `intendedUse[0..*]`, but clause
  5.2.4 flattens it: `credentials`, `purpose` and `intended_use_id` are top-level claims.
  A relying party with several intended uses holds several WRPRCs.
- **`exp` is optional** (Table 10) — an absent expiry is conformant, and revocation runs
  through the `status` claim (an IETF [Token Status List](Status-Lists), which
  `openvc.status.check_token_status` resolves; `verify_…` does not fetch it for you). The
  12-month ceiling (GEN-5.2.4-08) therefore binds only when `exp` is present. Pass
  `require_expiry=True` if your policy refuses a certificate that can only be revoked.
- **The CWT form has no claim-key mapping.** TS 119 475 presents its claim tables once,
  format-agnostically, and never allocates CBOR integer labels for them. The envelope
  (RFC 9052 + RFC 9360) is fully specified and implemented; the claims map is read
  accepting both the RFC 8392 registered integer keys and text keys — the only reading
  available to an issuer today. Treat the CWT lane as **provisional** until a real
  artifact exists to pin.

Only the JWT form’s signature profile is constrained further: GEN-5.2.1-04 requires
**JAdES baseline B-B** (ETSI TS 119 182-1). openvc implements a *verify subset* — the
signed-header profile and the chain validation — not a full JAdES library: no
signature-policy processing, no timestamps, no augmentation. Since JAdES clause 5.1.11
mandates a *header* `iat` that TS 119 475 Table 5 omits, the header `iat` is surfaced but
not required; the security-bearing timestamps are the payload’s.

Two known spec defects are absorbed rather than inherited: `intermediary` is spelled
`sname` in Table 10 and `name` in the Annex C example (both are read, via
`reg.intermediary_name`), and the intermediary identifier appears as both
`intermediary.sub` and `act.sub` (both via `reg.intermediary_identifier`).

## What this is not

- **The German BMI registration certificate** (`rc-rp+jwt`, from the eIDAS 2.0
  *Architekturkonzept*) is a **different profile** with different claim names. It is
  detected and refused by name rather than half-parsed under the wrong semantics.
- **Registrar workflows / certificate issuance.** openvc is a verifier/consumer:
  parse + validate only.
