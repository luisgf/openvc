# Data Integrity (embedded proofs)

[Data Integrity](https://www.w3.org/TR/vc-data-integrity/) embeds the proof in
the credential's JSON instead of wrapping it in a JWT, so the document stays a
plain JSON(-LD) object and the proof survives re-serialization. openvc
implements five cryptosuites behind one pattern — `add_proof` / pipeline
`verify_credential`:

| Cryptosuite | Suite class (`openvc.proof.*`) | Key | Canonicalization | Needs |
|---|---|---|---|---|
| `eddsa-rdfc-2022` | `data_integrity.DataIntegrityProofSuite` | Ed25519 | RDF (URDNA2015) | `[data-integrity]` (`pyld`) |
| `ecdsa-rdfc-2019` | `di_ecdsa_rdfc.EcdsaRdfcProofSuite` | P-256 / P-384 | RDF (URDNA2015) | `[data-integrity]` (`pyld`) |
| `eddsa-jcs-2022` | `di_jcs.EddsaJcsProofSuite` | Ed25519 | JCS (RFC 8785, stdlib) | core only |
| `ecdsa-jcs-2019` | `di_jcs.EcdsaJcsProofSuite` | P-256 / P-384 | JCS (RFC 8785, stdlib) | core only |
| `ecdsa-sd-2023` | `ecdsa_sd.EcdsaSdProofSuite` | P-256 | RDF + selective disclosure | `[data-integrity]` (`pyld`) |

The bundled JSON-LD contexts are served by an **offline document loader** — RDF
canonicalization never fetches a context from the network, and the loader stays
openvc's own (not pyld ≥3's `FrozenDocumentLoader`) so the exact context bytes
that feed canonicalization ship vendored in this package. Both `pyld` majors are
supported: the `>=2.0.4` floor and the revived 3.x line are verified against the
byte-for-byte golden fixtures, with CI exercising both edges.

Bundled contexts are handed to pyld tagged `static`, so their term definitions are
resolved once per process instead of on every canonicalization. A context you supply
through `extra_contexts` is served but **never** tagged: a tagged document is kept in a
cache keyed by context URL, so tagging caller-supplied documents would let one caller's
terms be used for another caller's document at the same URL. Every pyld call openvc makes
also gets a context resolver of its own (since 1.35.0), so nothing a call resolves — not
an injected context, and not an inline context that `@import`s a URL — is kept for the next
caller; only the resolution of the bundled contexts is shared. Injected contexts therefore
cost a little more per call and stay isolated from each other — the only safe trade in a
library that canonicalizes documents it did not author.

## RDF-canonicalized (`eddsa-rdfc-2022`)

<!-- docs: needs=pyld -->
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.data_integrity import DataIntegrityProofSuite

private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:9c1e-example",
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:alice"},
}
signed = DataIntegrityProofSuite().add_proof(
    credential, signing_key=issuer, verification_method=issuer.kid)

result = verify_credential(signed)      # format detected: data-integrity:eddsa
print(result.format, result.issuer)
```

## JCS — no `pyld`, pure stdlib

The JCS suites canonicalize with RFC 8785 (hand-rolled on the stdlib), so they
run on the bare core — same call shape:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

from openvc import verify_credential
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.di_jcs import EddsaJcsProofSuite

private_key = ed25519.Ed25519PrivateKey.generate()
public_raw = Ed25519SigningKey(private_key, kid="_").public_key_raw()
mb = encode_multibase(bytes([0xED, 0x01]) + public_raw)
issuer = Ed25519SigningKey(private_key, kid=f"did:key:{mb}#{mb}")

signed = EddsaJcsProofSuite().add_proof({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": f"did:key:{mb}",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:alice"},
}, signing_key=issuer, verification_method=issuer.kid)

result = verify_credential(signed)      # cryptosuite auto-detected
print(result.format, result.issuer)
```

## Selective disclosure: `ecdsa-sd-2023`

The issuer adds a **base proof** naming which pointers are `mandatory`; the
holder **derives** a proof revealing only selected pointers; the verifier sees
mandatory + selected claims, nothing else:

<!-- docs: needs=pyld -->
```python
from openvc.keys import P256SigningKey
from openvc.proof.ecdsa_sd import EcdsaSdProofSuite

KID = "did:key:zDnaExample#zDnaExample"
sk = P256SigningKey.generate(kid=KID)
suite = EcdsaSdProofSuite()

credential = {
    # The inline @vocab defines the custom subject terms; without it JSON-LD
    # expansion would silently drop them.
    "@context": ["https://www.w3.org/ns/credentials/v2",
                 {"@vocab": "https://vocab.example/"}],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:issuer",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:subject",
                          "name": "Ada Lovelace", "birthDate": "1815-12-10"},
}

base = suite.add_base_proof(          # issuer
    credential, signing_key=sk, verification_method=KID,
    mandatory_pointers=["/issuer", "/validFrom"])
derived = suite.derive_proof(         # holder
    base, selective_pointers=["/credentialSubject/name"])
result = suite.verify(derived, public_key_jwk=sk.public_jwk())   # verifier

print(result.credential["credentialSubject"])   # name disclosed, birthDate withheld
```

Make `credentialStatus` a **mandatory** pointer if you need it enforceable —
a selectively-disclosable status pointer can be withheld by the holder (see
the [Security model](Security-Model)).

## What verification enforces

Beyond the signature: the credential's **validity window**
(`validFrom` / `validUntil`), the proof's **`proofPurpose`** and `expires`,
and **issuer binding** — the proof's `verificationMethod` must be controlled
by the credential's `issuer` DID, so an attacker cannot sign someone else's
`issuer` with their own key.

The window is evaluated at `VerificationPolicy.now` (or the suite's `now=`):
`None` is the current time and a naive `datetime` is UTC. A `now` that is not a
`datetime`, such as an epoch `int` or an ISO string, raises `ProofError`, and so
does a `leeway_s` that is not a number. A negative or `NaN` leeway counts as 0.
These are configuration errors, so `verify_many` reports one on each item rather
than aborting the batch, with `require_not_expired=False` too. The `x5c`, mdoc,
relying-party certificate and Trusted List checks read `now` the same way, each
raising its own error class.

## The JSON must be what was signed

The RDF suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `ecdsa-sd-2023`) sign the **RDF
dataset** a document expands to. Every check above, and your own code, reads the
**JSON**. Many different JSON documents expand to the same dataset, so after the proof
verifies openvc validates the document's JSON-LD form ("context validation", VC Data
Integrity §2.4.1). It runs the same check before it signs. A document that fails
raises `ProofMalformed`:

- **`@context`** must start with the VC base context
  (`https://www.w3.org/ns/credentials/v2`, or `https://www.w3.org/2018/credentials/v1`
  passed through `extra_contexts`). After that, every entry is either a context URL the
  offline loader serves (bundled, or yours through `extra_contexts`) or an inline object
  that carries **only** `@vocab`, set to an absolute IRI. Inline term definitions are
  refused. Publish them as a context and pass it through `extra_contexts`.
- **Every member is spelled the way JSON-LD compaction would spell it.** A term no
  context defines is refused, because JSON-LD drops it from the dataset and the
  signature never covers its value. These are refused too:
  - a member keyed by its full IRI;
  - a keyword spelling, such as `@type` for `type`;
  - a nested `@context`;
  - a relative IRI, such as `"verificationMethod": "k"`;
  - an array directly inside another array, such as `"credentialStatus": [S1, [S2]]`
    or `[[S]]`. JSON-LD flattens it, so it signs the same dataset as `[S1, S2]`, but a
    reader looking for objects skips the inner array. A term your context declares with
    `"@container": "@list"` may still hold a list of lists: compaction writes that one
    back nested, so it is the compacted form. An `@json` value whose top-level array
    holds arrays (`"_sd": [["x"]]`) is refused too, because pyld compacts it lossily
    (to `"x"`); arrays nested deeper inside the JSON value are fine.

  Only two variations are accepted, because JSON-LD treats each pair as the same value:
  a one-element array and its element (as a member's value, never inside another
  array), and `{"id": X}` and `X`.
- **A member a trusted context defines is spelled by its term.** Compaction keeps a
  value that does not match its term's definition under the property's full IRI, a
  compact IRI or an `@vocab` suffix: a `validUntil` written as a plain string under
  `https://www.w3.org/2018/credentials#validUntil` (the term requires an
  `xsd:dateTime`), or a `credentialStatus` given as a string. That spelling *is* the
  compacted form, so the rule above accepts it, while the expiry and status checks read
  only the term. Any key, or `type` value, that stands for an IRI one of the verifier's
  contexts defines a term for must therefore be that term. That means every context
  the loader serves (the bundled ones and your `extra_contexts`), whether or not the
  document lists it: the `@context` is the holder's to edit, so a holder could
  otherwise drop a status-list context you inject, add `{"@vocab":
  "https://w3id.org/vc/"}`, and write the entry's type as
  `status-list#StatusList2021Entry`. That is the same signed data, but the status
  check would skip it as a type it does not know. When the VC base context defines a
  term for the IRI, it must be the base context's term: a context you pass in
  `extra_contexts` that gives `validUntil`'s IRI another name (`until`), or a shorter
  one compaction would prefer over `credentialStatus`, is refused rather than allowed
  to hide the member. The IRIs the checks after the proof read are pinned to the one
  key they read, whatever the loader serves: `validFrom`, `validUntil`, `issuanceDate`,
  `expirationDate`, the proof's `expires`, `credentialStatus`, `credentialSchema`, and
  the entry types and members of both `BitstringStatusListEntry` and
  `StatusList2021Entry`. openvc does not serve the VC 1.1 or StatusList2021 contexts by
  default, so without this a holder could re-compact an issuer's VC 1.1 credential onto
  the VC 2.0 base alone and spell `expirationDate` by its IRI, out of the expiry
  check's sight. A term your own context gives one of those IRIs is refused for the
  same reason. The keys inside an `@json` value such as `_sd` are not checked.

  The rule does not track which of your contexts a credential uses, nor where a scoped
  term is in effect. An IRI that any served context defines a term for, in any scope,
  must be written through a term everywhere: in a credential that never lists that
  context, and at a node where that term is not active and the IRI spelling is what
  compaction emits. The more contexts you inject, the more full-IRI spellings of their
  IRIs are refused, and one you inject that cannot be read refuses every RDF
  credential. For example, a `credentialSubject` property written `dcterms:created` or
  `https://w3id.org/security#nonce` is refused, because the VC base context defines
  `created` and `nonce` inside its `DataIntegrityProof` scope. For an IRI only your
  own context defines, add a term for it to that context (in `extra_contexts`) and
  write the term. An IRI the VC base context defines has no other accepted spelling,
  so use a different property. An IRI no served context names a term for (your own
  extension property) is not affected, unless it is one of the IRIs the policy reads.
- **A `credentialStatus` entry is described under `credentialStatus`.** RDF lets a
  node be described under any property that references it, so an entry the issuer also
  names from, say, `relatedResource` could otherwise be moved there, leaving only
  `{"id": X}` where the status check looks. The status check reads only the
  credential's own, top-level `credentialStatus`, so an entry there whose `id` is
  described anywhere else in the document is refused, including under the
  `credentialStatus` of a nested node (a subject typed `VerifiableCredential`, say).
  An exact copy of the entry is the exception. An embedded credential, such as an OB
  3.0 endorsement, may repeat the outer `credentialStatus` verbatim, and RDF merges
  the two into the same statements. A copy that differs in any member is refused.
- **On `ecdsa-sd-2023`, one signed blank node is one node in the JSON.** A derived
  proof's label map, which the holder writes, must give each blank node its own
  label, and the verifier canonicalizes the document as presented, as VC-DI-ECDSA's
  verifier does. A `urn:bnid:` IRI there is an IRI, not a blank node. Otherwise two
  JSON nodes could be the issuer's one node, which would let a holder move an id-less
  status entry past the rule above, or give a node the issuer signed without an `id`
  one of its own choosing.
- **Nothing about the document is stated outside it.** `@included`, `@reverse`, a
  top-level `@graph`, and a second description of the document's own node nested
  inside it are all refused.
- **Nothing in the JSON is dropped on the way to RDF** (JSON-LD "safe mode"). The RDF
  conversion silently drops a statement whose subject, property or IRI value is not a
  well-formed absolute IRI, such as an `id` containing whitespace or a property from a
  blank-node `@vocab`. It also leaves out `@index` and `@direction` annotations. All of
  these are refused, because their values would not be signed.
- **A type named like a term you serve is that term.** A top-level `type` value that
  is a term a served context defines must stand, in the credential, for one of the
  IRIs that term is defined as. Otherwise a holder could swap the issuer's context for
  an inline `@vocab` that ends inside the signed type IRI (`"…/vocab#Alumni"` for
  `…/vocab#AlumniDegreeCredential`) and show that type as `"DegreeCredential"`.

**`expected_types` is matched by IRI on these suites.** The signature covers each
type's IRI, not how the JSON spells it, and the holder chooses where an inline `@vocab`
ends. So each name in `VerificationPolicy.expected_types` is resolved through the
contexts the verifier serves (bundled or `extra_contexts`), never through the
credential's own `@context`, and must name one of the credential's expanded types. A
name a served context defines stands for its IRIs, any other name for each served
`@vocab` plus it, and a full or compact IRI for itself. A type only an inline `@vocab`
names therefore needs one of two things: serve a context that names it (the published
one, or one that holds just that `@vocab`, such as
`{"https://www.w3.org/ns/credentials/examples/v2": {"@context": {"@vocab":
"https://www.w3.org/ns/credentials/examples#"}}}`), which the credential need not list,
or pin the full type IRI. If your own code reads `type` from the JSON, compare expanded
IRIs, or let `expected_types` do it. The JCS suites, VC-JWT and SD-JWT compare the
strings the issuer signed, as before.

The bundled v2 context has no `@vocab`, so a custom claim needs a definition. Use an
inline `{"@vocab": "…"}`, as in the selective-disclosure example above, or your own
context through `extra_contexts`. openvc trusts what you put in `extra_contexts`
for IRIs the VC base context does not define: a term it gives such an IRI is taken as
that IRI's spelling. A second name for a core VC term (`validUntil`,
`credentialStatus`, …) is refused, as above. Inject only contexts you have reviewed.

In a `VerifiablePresentation`, the embedded `verifiableCredential` entries are skipped
here. Each one is verified on its own, under its own `@context`. The JCS suites sign
the JSON itself, so none of this applies to them.

## Conformance

`eddsa-rdfc-2022` reproduces the official W3C
[vc-di-eddsa](https://www.w3.org/TR/vc-di-eddsa/) test vector byte-for-byte.
`ecdsa-rdfc-2019` and `ecdsa-sd-2023` verify the official
[vc-di-ecdsa](https://www.w3.org/TR/vc-di-ecdsa/) vectors and reproduce their
published intermediates (ECDSA signing is randomized, so byte-identical proofs
are not possible). The recorded vectors live in `tests/fixtures/` as the drift
alarm.
