# Status lists (revocation)

A status list is a bitstring an issuer publishes; each credential points at
one bit of it (`credentialStatus`), and flipping the bit revokes (or suspends)
the credential without reissuing anything. openvc implements **both** wire
encodings behind **one interface** — the W3C
[Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)
(a W3C Recommendation since 2025-05) and
the IETF [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
(draft-21, IESG-approved and in the RFC Editor queue as of 2026-07) — and can
**check and issue** either. The Token Status List codec is pinned byte-for-byte to
the draft's §4.1 worked examples, and the Bitstring codec to the W3C REC's own
`encodedList` example (plus a third-party Digital Bazaar vector).

The Bitstring `encodedList` is **multibase**-encoded (a leading `u`, base64url) as the
REC mandates: `decode_bitstring` consumes real W3C lists that carry the `u` prefix and
still reads legacy prefix-less lists, and `encode_bitstring` emits the conformant `u`.

## Issue a list, stamp a credential, revoke it

```python
from openvc.status import (
    build_status_list_credential,
    build_status_list_entry,
    check_credential_status,
    new_bitstring,
    set_status_bit,
)

LIST_URL = "https://issuer.example/status/1"
INDEX = 17

# A credential the issuer hands out, pointing at bit 17 of the list.
credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"], "issuer": "did:example:issuer",
    "credentialStatus": build_status_list_entry(
        status_list_credential=LIST_URL, index=INDEX),
    "credentialSubject": {"id": "did:example:alice"},
}


def status_list(revoked: bool):
    """The (unsigned) status-list credential a resolver would fetch + verify."""
    bits = new_bitstring(1024)
    if revoked:
        set_status_bit(bits, INDEX, 1)
    return build_status_list_credential(
        id=LIST_URL, issuer="did:example:issuer", bitstring=bits)


live, dead = status_list(revoked=False), status_list(revoked=True)
print(check_credential_status(credential, resolve_status_list=lambda _u: live).revoked)
print(check_credential_status(credential, resolve_status_list=lambda _u: dead).revoked)
```

In production, sign the status-list credential like any other credential and
serve it at `LIST_URL`.

## Fail-closed by default in the pipeline

`verify_credential` treats a **declared status it cannot check as a
rejection**: if the credential carries `credentialStatus` and you supplied no
resolver, it fails. Supply one of the blessed resolvers — they fetch through
the SSRF guard **and verify the fetched list's own proof before trusting a
single bit**:

<!-- docs: no-run -->
```python
from openvc import verify_credential
from openvc.resolvers import (
    default_status_list_resolver,          # W3C Bitstring status lists
    default_status_list_token_resolver,    # IETF Token Status List (JWT)
)

result = verify_credential(
    token,
    resolve_status_list=default_status_list_resolver(),
    resolve_status_list_token=default_status_list_token_resolver(),
)
```

Opting *out* (accepting a credential without checking its declared status) is
an explicit policy decision, not a default.

## Hardening you get for free

- **Anti-swap**: a status-list token's `sub` must equal the URI it was fetched
  from, so a valid list cannot vouch for a different one.
- **Decompression bomb cap**: lists decompress incrementally with a hard
  output bound, so a tiny malicious payload cannot OOM the verifier
  (fail-closed `StatusListError`).
- **Issuer binding (opt-in)**: by default a status list is authenticated but its
  issuer is unconstrained — delegation of status hosting is spec-legal. If your
  issuers self-host their status lists, set
  `VerificationPolicy(require_status_issuer_binding=True)` to require the resolved
  list's issuer to be the credential's issuer (add trusted delegates via
  `status_issuer_allowlist`); a mismatch raises `StatusListIssuerUntrusted`. See
  [ADR-0006](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0006-status-list-issuer-binding.md).
- **SD caveat**: keep the `credentialStatus` pointer **non**-selectively
  disclosable, or a holder can withhold it — see [SD-JWT VC](SD-JWT-VC) and
  the [Security model](Security-Model).
