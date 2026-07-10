# Walkthrough: a Spanish university credential, end to end

Spain's university-wallet pilot (SGAD + **FNMT-RCM** + UC3M/UM/URV) and the **DC4EU**
education rulebook v3.0 describe exactly the stack openvc verifies: FNMT anchors on the
Spanish **TLv6** trusted list, EBSI TIR accreditation, and SD-JWT VC / VCDM envelopes.
This walkthrough verifies a higher-education diploma **with openvc alone** — the trust
decision and the credential — offline.

The runnable version is
[`examples/11_spanish_university_credential.py`](https://github.com/luisgf/openvc/blob/main/examples/11_spanish_university_credential.py).

## The two halves of the trust decision

A verifier answers two questions, and openvc has an API for each:

1. **Is the issuer trusted?** The university's document-signer certificate must chain to
   an **FNMT-RCM** root that appears on the **Spanish Trusted List** (ETSI TS 119 612,
   TLv6), reached from the EU **List of Trusted Lists (LOTL)**. `openvc.trustlist` fetches
   and XAdES-verifies those lists into a set of X.509 anchors; `openvc.x5c` validates the
   signer's chain to one of them and binds it to the issuer id.
2. **Is the credential valid?** The diploma is an **SD-JWT VC** signed by that same
   FNMT-anchored key, with the student's wallet key binding.

## 1 — FNMT anchors from the Spanish trusted list

In production the anchors come from the trusted list; `openvc.trustlist` returns them as
plain `x509.Certificate` objects (see [Trust anchors](Trust)):

<!-- docs: no-run -->
```python
from openvc.trustlist import consume_trust_list

anchors = consume_trust_list(
    "https://ec.europa.eu/tools/lotl/eu-lotl.xml", territories={"ES"})
fnmt_anchors = anchors.certificates()      # FNMT-RCM roots on the ES list
```

The university's document-signer chain is then validated to those anchors and bound to the
issuer id (the diploma's `iss`, matched against the certificate SAN), which yields the
issuer's public key:

<!-- docs: no-run -->
```python
from openvc.x5c import resolve_x5c_key

issuer_jwk = resolve_x5c_key(x5c_chain, "https://sede.uc3m.es", trust_anchors=fnmt_anchors)
```

## 2 — The diploma as an SD-JWT VC

The diploma is a DC4EU **European Higher-Education Diploma** (`vct:
https://dc4eu.eu/credentials/EUHED`), issued by the university's key and bound to the
student's wallet key. It is verified with the **FNMT-anchored** `issuer_jwk` from step 1 —
so a diploma only verifies if its signer is trusted on the Spanish list:

<!-- docs: no-run -->
```python
from openvc.proof.sd_jwt import SdJwtVcProofSuite

result = SdJwtVcProofSuite().verify(
    presentation, public_key_jwk=issuer_jwk,
    audience="https://empleador.example", nonce=nonce,
    require_key_binding=True, expected_vct="https://dc4eu.eu/credentials/EUHED")
# result.issuer, result.vct, result.key_bound, result.claims["title"], …
```

Selectively-disclosable claims (e.g. `final_grade`, `given_name`) let the student reveal
only what an employer needs. Run the example above for the full offline flow.

## The EBSI accreditation path (complementary)

DC4EU runs over **EBSI** trust registries too: an issuer holds an accreditation in the
EBSI Trusted Issuers Registry (TIR), recursively anchored to a Root Trusted Accreditation
Organisation. `openvc_ebsi.verify_ebsi_badge` verifies an EBSI-issued VC-JWT and walks that
accreditation chain (needs the `[ebsi]` extra and registry access — see
[Trust anchors](Trust)):

<!-- docs: no-run -->
```python
from openvc_ebsi.verify import verify_ebsi_badge

badge = verify_ebsi_badge(
    token, resolver=ebsi_resolver, proof_suite=vc_jwt_suite,
    expected_types=["VerifiableEducationalID"],
    trust_anchors={"did:ebsi:zRootTAO…"})   # the recursive chain to a trusted RootTAO
```

The two anchors are complementary: the **FNMT / Spanish trusted list** is the eIDAS/national
route, and **EBSI TIR** is the DC4EU/ecosystem route. A verifier can require either or both.

## Notes

- The runnable example mints an FNMT-analog root offline (no network); swap it for real
  `openvc.trustlist` anchors in production.
- SD-JWT VC issuance does not yet emit an `x5c` header, so the walkthrough validates the
  signer chain (`resolve_x5c_key`) and verifies the SD-JWT VC with the resulting key as two
  steps ([#94](https://github.com/luisgf/openvc/issues/94) tracks folding `x5c` into the
  SD-JWT VC issuer JWT so `verify_credential(..., x5c_trust_anchors=…)` does both at once).
