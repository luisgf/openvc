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

The builders hold what they mint to the rules the verifier applies, so a bad value
fails at build time with a `StatusListError` instead of in the field:

- `index` is an `int` below 2^27, the same rule as the check side. A `bool`, a
  `float` (`NaN` included), a string, a negative or an oversized index raises. The
  W3C entry still *emits* it as the base-10 string the spec asks for, and the IETF
  `idx` stays a JSON integer.
- `status_list_credential`, `status_purpose` and the IETF `uri` are non-empty strings.
- A list is a `bytes`, `bytearray`, `memoryview` or `array.array` (wrap any other
  buffer in `memoryview()`; an `int` is refused, where it used to become a zeroed
  list, and so is anything else `bytes()` would have taken, a `list` or `tuple` of
  ints say: pass `bytes(values)`). A non-contiguous `memoryview` counts as the bytes
  it shows. It may not exceed the 16 MiB the verifier decompresses:
  `build_status_list_credential` and `build_status_list_token`
  refuse a longer one, and `new_bitstring(size)` / `new_status_list(size, bits=...)`
  refuse a `size` that would need it: 2^27 one-bit statuses, but only 2^24 at 8 bits.
- The time inputs and `ttl` follow the verifier's shape rules too, and a naive
  `datetime` is read as UTC in both builders (the section below).

`get_status_bit`, `set_status_bit`, `get_status` and `set_status` hold their `index` to
the same type rule (the list's own length bounds it): a `bool` is no longer read as
index 1, and a `float` is a `StatusListError`, not a `TypeError`. `set_status` also
wants an `int` `value`, while `set_status_bit` still reads its `value` for truthiness.

This is a behaviour change in 1.32.3: some inputs that used to build something are
now refused. Most minted an entry or a list that the verifier then refused in the
field, or raised a bare `TypeError` (a `bool`, `float` or oversized index, a list past
16 MiB, a `bits` of `True`). Some built an artefact that worked and are refused only
because they were never the documented types. Pass these instead:

- anything `bytes()` accepted as the list that is not a buffer (a `list`, `tuple`,
  `range`, generator, `dict` or an object with `__bytes__`): `bytes(values)`;
- an integral `Decimal` or `Fraction` as the index: `int(index)`;
- a `bool` or `Fraction` `bits` or `size`: the `int` (`1`);
- a falsy `status_purpose` (`""`, `None`, `0`) or an empty `id` on the list credential:
  the purpose (`"revocation"` is the default) and the URL.

The [CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) entry for
1.32.3 lists every case.

### Times and `ttl`

`valid_from` / `valid_until` (the credential) are a `datetime` or `None`;
`issued_at` / `expires` (the token) are a `datetime` or a finite number of epoch
seconds, so `time.time()` still works. A `datetime` is read the way every openvc
clock check reads one: **a naive value is UTC**, never the host's local time, and an
aware one is converted. Both builders agree, so one naive `datetime` is the same
instant in the credential's `validFrom` and in the token's `iat`, on any host:

```python
from datetime import datetime

from openvc.status import build_status_list_credential, new_bitstring

naive = datetime(2026, 1, 1, 12, 0)             # UTC, whatever zone this host is in
vc = build_status_list_credential(
    id="https://issuer.example/status/1", issuer="did:example:issuer",
    bitstring=new_bitstring(64), valid_from=naive, ttl=300)
assert vc["validFrom"] == "2026-01-01T12:00:00Z"
```

These are a `StatusListError` at build time, before anything is signed:

- a `valid_from` / `valid_until` that is not a `datetime` (an ISO string, an epoch
  number, a `date`), and a `datetime` with no UTC equivalent: year 1 at `+01:00`, or
  a `tzinfo` that raises;
- an `issued_at` / `expires` that is a `bool`, a digit string (`"1700000000"`), a
  `date`, a `timedelta`, `NaN`, `inf`, or an integer no float holds (`10**400`) — the
  last would have been signed and then refused by `verify_status_list_token`, which
  only accepts a finite NumericDate;
- a `ttl` that is not `None` or a positive `int`: a `bool`, a `float` (`NaN` and `inf`
  included, which are not JSON), a string, `0`, a negative number, a `list`. The IETF
  `ttl` is seconds and the W3C one milliseconds; the builder does not convert.

The order of a window is not checked: a past `expires`, an `issued_at` in the future
or an `expires` before `issued_at` build, and `verify_status_list_token` /
`VcJwtProofSuite.verify` refuse them when they read the artefact.

This is a behaviour change in 1.32.4. A digit string or a `bool` for `issued_at` /
`expires`, a `Decimal` or `Fraction` there (pass `int(x)`), and a `ttl` that is not a
positive `int` used to build and are now refused. A naive `valid_from` / `valid_until`
on a host that is not on UTC now yields its UTC reading, a different `validFrom` /
`validUntil` string from before for the same call (it used the host's local zone): pass
an aware `datetime` if you meant local time. The
[CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) entry for 1.32.4
has the list.

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
an explicit policy decision, not a default. To keep checking status but accept a
revoked credential anyway, set `VerificationPolicy(require_not_revoked=False)`
and read `result.status.revoked`; suspension still rejects. See
[Waiving expiry or revocation](Getting-Started#waiving-expiry-or-revocation).

## Hardening you get for free

- **Anti-swap**: a status-list token's `sub` must equal the URI it was fetched
  from, so a valid list cannot vouch for a different one.
- **Decompression bomb cap**: lists decompress incrementally with a hard
  output bound, so a tiny malicious payload cannot OOM the verifier
  (fail-closed `StatusListError`).
- **The issuer side obeys the same rules**: the builders never mint an index or a list
  the check side would refuse (see [Issue a list](#issue-a-list-stamp-a-credential-revoke-it)).
- **Strict index parsing**: a credential's `statusListIndex` must be a base-10
  string of ASCII digits (a JSON integer is tolerated); the IETF `idx` must be a
  JSON integer. A `bool`, any `float` (`NaN`, `Infinity`, `1e400`, `3.7`), a sign,
  whitespace, an underscore, a non-ASCII digit, or an index past the largest list
  openvc decodes (2^27 statuses) is a typed `StatusListError` — even under
  `require_status=False`: a malformed entry of a recognised type is never
  skipped. In `verify_many` it fails only that item.
- **Issuer binding (opt-in)**: by default a status list is authenticated but its
  issuer is unconstrained — delegation of status hosting is spec-legal. If your
  issuers self-host their status lists, set
  `VerificationPolicy(require_status_issuer_binding=True)` to require the resolved
  list's issuer to be the credential's issuer (add trusted delegates via
  `status_issuer_allowlist`); a mismatch raises `StatusListIssuerUntrusted`. See
  [ADR-0006](https://github.com/luisgf/openvc/blob/main/docs/adr/ADR-0006-status-list-issuer-binding.md).
  The binding compares the `issuer` named in the list's **body**. The default
  resolvers refuse a list whose body names an issuer other than the one its
  signature was verified for (`StatusListError`). Before 1.31.0, an IETF
  `dc+sd-jwt` list signed by an attacker could name the victim there and clear
  the revocation bit. A custom `resolve_status_list` must uphold the same rule:
  return a list whose `issuer` you have authenticated, for example by comparing it
  with the `result.issuer` of the `verify_credential` call that checked the list.
- **SD caveat**: a selectively disclosable status pointer is one the holder can
  withhold, and a withheld one looks like no status at all. openvc's SD-JWT VC
  `issue()` refuses to make `status` or `credentialStatus` disclosable, and
  `verify()` rejects a presentation that discloses either, or a part of one. A
  third-party SD-JWT VC whose issuer made it disclosable still verifies when the
  holder withholds it — see [SD-JWT VC](SD-JWT-VC) and the
  [Security model](Security-Model). For `ecdsa-sd-2023`, keep `credentialStatus`
  among the mandatory pointers.
