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
- The strings an artefact names are checked too: the credential's `issuer`,
  `subject_id` and `contexts`, an entry's `id` and the token's `issuer`. An empty or
  falsy value is an error, not a way to ask for the default (the subsection on issuer, subject, contexts and the entry `id`, below).

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
  number, a `date`);
- in any of the four parameters, a `datetime` with no UTC equivalent between years 1 and
  9999 (year 1 at `+01:00`, `9999-12-31T23:00` at `-05:00`) or whose `tzinfo` raises.
  Both builders read a `datetime` the same way, and the token takes its epoch from the
  plain `datetime` that reading returns, never from the object the caller passed;
- an `issued_at` / `expires` that is a `bool`, a digit string (`"1700000000"`), a
  `date`, a `timedelta`, `NaN`, `inf`, or an integer no float holds (`10**400`) — the
  last would have been signed and then refused by `verify_status_list_token`, which
  only accepts a finite NumericDate;
- a `ttl` that is not `None` or a positive `int`: a `bool`, a `float` (`NaN` and `inf`
  included, which are not JSON), a string, `0`, a negative number, a `list`. The IETF
  `ttl` is seconds and the W3C one milliseconds; the builder does not convert.

The order of a window is not checked, by the builders or by the verifiers: a past
`expires`, an `issued_at` in the future, an `expires` before `issued_at` and a
`valid_until` before `valid_from` all build. `verify_status_list_token` /
`VcJwtProofSuite.verify` refuse the artefact when the time they read it at falls outside
the window by more than their leeway (60 seconds by default), so a window inverted by less
than the leeway is still accepted.

This is a behaviour change in 1.32.4. A digit string or a `bool` for `issued_at` /
`expires`, a `Decimal` or `Fraction` there (pass `int(x)`), and a `ttl` that is not a
positive `int` used to build and are now refused, and so is a `datetime` that has no UTC
equivalent, which `build_status_list_token` used to sign as an `iat` / `exp` (year 1 at
`+01:00` as `-62135600400`). A naive `valid_from` / `valid_until`
on a host that is not on UTC now yields its UTC reading, a different `validFrom` /
`validUntil` string from before for the same call (it used the host's local zone): pass
an aware `datetime` if you meant local time. The
[CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) entry for 1.32.4
has the list.

### Issuer, subject, contexts and the entry `id`

The strings a list names used to be copied as given, and the proof suite you signed with
decided whether they mattered: a `contexts` string was accepted by VC-JWT and by
`eddsa-jcs-2022` and refused only at `add_proof` by `eddsa-rdfc-2022`. The builder is the
one place that can decide for all of them, so it holds these to what the verifier reads:

| Parameter | Accepted | `StatusListError` |
|---|---|---|
| `issuer`, `build_status_list_credential` | a non-empty string, or an object with a non-empty string `id` and no `@id` (other members, such as `name`, are carried as given) | `None`, `""`, a number, `bytes`, a list; an object with no string `id`, or with an `@id`, equal or not |
| `subject_id` | `None` (the subject is `<id>#list`) or a non-empty string | `""`, `0`, `[]`, `{}`, any non-string |
| `contexts` | `None` (the VC 2.0 context) or a non-empty `list` / `tuple` that starts with a VC base context, followed by context URLs (non-empty strings) or inline context objects | a bare string (it was read one character at a time), a `dict`, an iterator, an empty list, a first entry that is not a VC base context, any other entry that is not a non-empty string or an object |
| `id`, `build_status_list_entry` | `None` (the entry has no `id`) or a non-empty string | `""`, `0`, `[]`, `{}`, any non-string |
| `issuer`, `build_status_list_token` | `None` (no `iss` claim) or a non-empty string | `""`, `0`, `[]`, `{}`, any non-string |

`None` is the only way to ask for a default. An empty or falsy value (`subject_id=""`,
`contexts=[]`, `contexts=0`) used to be replaced by the default without a word and is now
an error. A VC base context is `https://www.w3.org/ns/credentials/v2` or
`https://www.w3.org/2018/credentials/v1`; the RDF suites and the credential type need one
first. A context URL that is not bundled with openvc still needs `extra_contexts` on the
`eddsa-rdfc-2022` suite.

```python
from openvc.status import StatusListError, build_status_list_credential, new_bitstring

VC2 = "https://www.w3.org/ns/credentials/v2"
vc = build_status_list_credential(
    id="https://issuer.example/status/1",
    issuer={"id": "did:example:issuer", "name": "Example issuer"},
    bitstring=new_bitstring(64),
    contexts=[VC2, {"@vocab": "https://example.org/terms#"}])
assert vc["credentialSubject"]["id"] == "https://issuer.example/status/1#list"

try:
    build_status_list_credential(
        id="https://issuer.example/status/1", issuer="did:example:issuer",
        bitstring=new_bitstring(64), contexts="https://example.org/ctx")
except StatusListError as exc:
    print(exc)          # contexts must be None or a non-empty list of context URLs ...
```

Not checked, by design: that an identifier is a URI (`"not a uri"` builds; only key
resolution, and the RDF suites at `add_proof`, refuse one), its length, and the members of
an `issuer` object besides `id` and `@id`. A token built without `issuer` is still allowed,
and `default_status_list_token_resolver` refuses it (`StatusListError`: no `iss` to find
the key with), so pass the issuer unless you resolve the key some other way.

This is a behaviour change in 1.32.5. These used to build and now raise: an `issuer` that
is not a non-empty string or an object with a string `id` and no `@id`; a `subject_id`,
entry `id` or token `issuer` that is not a non-empty string; `contexts` that is a string,
a `dict`, an iterator or a list with an entry that is neither a non-empty string nor an
object, or whose first entry is not a VC base context; and a falsy `subject_id` or
`contexts` that fell back to the default (pass `None`, or leave it out). Inputs that
already raised a bare `TypeError` (`contexts=5`, a `bytes` issuer) now raise
`StatusListError`. The
[CHANGELOG](https://github.com/luisgf/openvc/blob/main/CHANGELOG.md) entry for 1.32.5
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
