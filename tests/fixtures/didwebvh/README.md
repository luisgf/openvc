# did:webvh golden vectors

Real `did.jsonl` logs recorded verbatim from the reference **Rust** implementation
[`decentralized-identity/didwebvh-rs`](https://github.com/decentralized-identity/didwebvh-rs)
(`tests/test_vectors/test_suite/`, did:webvh **v1.0**), Apache-2.0. They pin
`openvc.did.did_webvh` to what other implementations produce — the drift alarm — rather
than to shapes this resolver also generates:

| File | Scenario exercised |
|---|---|
| `basic-create.jsonl` | genesis entry — SCID derivation + entryHash + `eddsa-jcs-2022` proof |
| `key-rotation.jsonl` | rotate to a new key, authorized by the **previous** entry's key (no pre-rotation) |
| `pre-rotation.jsonl` | an entry that **sets** `nextKeyHashes` (arms pre-rotation) |
| `pre-rotation-consume.jsonl` | the next entry **consumes** it — its `updateKeys` hash into the commitment |
| `multi-update.jsonl` | a three-version chain |
| `deactivate.jsonl` | a log that ends in `deactivated: true` |

`tests/test_did_webvh.py` resolves each of these and tampers them (mutated state, corrupt
proof, forged SCID, renumbered/dropped entries, unauthorized signer) to assert the
resolver fails closed.
