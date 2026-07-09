# Relying-party certificates (EUDI WRPAC)

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

## What this is not

- **The registration certificate (WRPRC)** — the *entitlements / intended-use*
  artifact — is a signed **JWT or CWT** (ETSI TS 119 475), not an X.509 certificate,
  and its claim mapping is not finalised yet. It is tracked separately and is out of
  scope for `openvc.rp_cert` today.
- **Registrar workflows / certificate issuance.** openvc is a verifier/consumer:
  parse + validate only.
