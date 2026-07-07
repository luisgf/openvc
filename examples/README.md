# openvc examples

Small, self-contained, **runnable** scripts for the main flows. Each generates its
own `did:key` keys, so they need no network and no DID setup — the pipeline's
default resolver resolves `did:key` offline.

```sh
pip install -e ".[all]"            # or: pip install 'openvc-core[data-integrity]'
python examples/01_verify_pipeline.py
```

| Script | Shows |
|---|---|
| `01_verify_pipeline.py` | issue a VC-JWT, verify it with the one-call `verify_credential` pipeline (format detection, key resolution, type policy) |
| `02_sd_jwt_presentation.py` | SD-JWT VC: selective-disclosure issuance, holder presentation with a Key Binding JWT, verification |
| `03_data_integrity.py` | embed an `eddsa-rdfc-2022` Data Integrity proof, verify it through the pipeline *(needs the `[data-integrity]` extra)* |
| `04_status_list.py` | publish a Bitstring status list, stamp a `credentialStatus`, revoke by flipping the bit |
| `05_vp_jwt_presentation.py` | a holder wraps a credential in a VP-JWT bound to a verifier (`aud`/`nonce`); verify cascade-checks each embedded credential with holder binding |
| `06_remote_signing_key.py` | a remote `SigningKey` backend (AWS KMS / Vault / PKCS#11 pattern) — the private key never enters the process; shows the DER→R‖S conversion ES256 needs |
| `07_jcs_no_pyld.py` | JCS Data Integrity (`eddsa-jcs-2022` / `ecdsa-jcs-2019`): whole-document proofs canonicalized with RFC 8785 — verified through the pipeline with **no `[data-integrity]` extra** |
| `08_openid4vp_verify.py` | verify a stateless OpenID4VP 1.0 `vp_token`: a holder presents an SD-JWT VC + KB-JWT bound to the verifier's `nonce`/`client_id`; the verifier checks the DCQL-keyed shape and the binding |
| `09_haip_encrypted_response.py` | HAIP `direct_post.jwt`: the wallet returns the `vp_token` inside a JWE (`ECDH-ES`/AES-GCM); the verifier decrypts with its `KeyAgreementKey` and verifies in one call (`verify_encrypted_vp_response`) |

`_common.py` holds the shared `did_key_ed25519()` / `did_key_p256()` helpers that
mint a signing key already keyed to its `did:key` verification method.
