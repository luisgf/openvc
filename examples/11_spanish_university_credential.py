"""
11 — A Spanish university credential, verified end to end with openvc alone.

The stack from Spain's university-wallet pilot (SGAD + FNMT-RCM + UC3M/UM/URV) and the
DC4EU education rulebook v3.0: a higher-education diploma carried as an **SD-JWT VC**,
issued by a university whose signing certificate is anchored to an **FNMT-RCM** root on
the **Spanish (TLv6) trusted list**. openvc does the two halves of the trust decision,
offline and with no network:

  1. **Issuer trust** — validate the university's document-signer certificate chain to the
     FNMT anchor (the EU LOTL → ES Trusted List → x5c path) and bind it to the issuer id.
  2. **Credential** — verify the SD-JWT VC signed by *that same* FNMT-anchored key, with
     the holder's key binding.

The EBSI TIR accreditation path (``openvc_ebsi.verify_ebsi_badge``) is the complementary
trust anchor for the DC4EU/EBSI ecosystem — see the wiki walkthrough (it needs the EBSI
registry, so it is not exercised in this offline example).

Run:  python examples/11_spanish_university_credential.py
"""
from __future__ import annotations

import base64
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openvc.keys import Ed25519SigningKey, P256SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.x5c import resolve_x5c_key

ISS = "https://sede.uc3m.es"                 # the university's issuer id (in the cert SAN)
VCT = "https://dc4eu.eu/credentials/EUHED"   # DC4EU European Higher-Education Diploma
NOW = dt.datetime.now(dt.timezone.utc)


def _cert(subject, issuer_cn, issuer_key, subject_pubkey, *, ca, san=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_pubkey).serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:                                        # webpki CA policy requires keyCertSign
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


# --- 1. The Spanish trusted list: an FNMT-RCM root anchors the university's signer ------
# In production these anchors come from the EU LOTL -> the Spanish Trusted List (ETSI TS
# 119 612, TLv6), fetched and XAdES-verified by openvc.trustlist. Here we mint an
# FNMT-analog root and a UC3M document-signer certificate chained to it, offline.
fnmt_key = ec.generate_private_key(ec.SECP256R1())
fnmt_root = _cert("FNMT-RCM AC RAIZ (demo)", "FNMT-RCM AC RAIZ (demo)",
                  fnmt_key, fnmt_key.public_key(), ca=True)

uc3m_priv = ec.generate_private_key(ec.SECP256R1())          # ES256 — the EUDI curve
uc3m_key = P256SigningKey(uc3m_priv, kid="uc3m-signer")
uc3m_ds = _cert("UC3M Document Signer (demo)", "FNMT-RCM AC RAIZ (demo)",
                fnmt_key, uc3m_priv.public_key(), ca=False,
                san=[x509.UniformResourceIdentifier(ISS)])
x5c = [base64.b64encode(uc3m_ds.public_bytes(serialization.Encoding.DER)).decode("ascii")]

# openvc validates the chain to the FNMT anchor AND binds the issuer id to the cert SAN,
# returning the issuer's public key — this is the "is the signer trusted?" decision.
issuer_jwk = resolve_x5c_key(x5c, ISS, trust_anchors=[fnmt_root], now=NOW)
print("1. Issuer trust (FNMT anchor on the Spanish trusted list)")
print("   UC3M document-signer chains to:", fnmt_root.subject.rfc4514_string())
print("   issuer bound to SAN:", ISS, "| key:", issuer_jwk["crv"])

# --- 2. The diploma as an SD-JWT VC, signed by that FNMT-anchored key -------------------
holder = Ed25519SigningKey.generate(kid="student-wallet")
suite = SdJwtVcProofSuite()
diploma = suite.issue(
    {"iss": ISS,
     "family_name": "García Ruiz", "given_name": "Lucía",
     "title": "Grado en Ingeniería Informática",
     "awarding_institution": "Universidad Carlos III de Madrid",
     "eqf_level": 6, "final_grade": "9.2/10", "date_of_award": "2026-06-30"},
    signing_key=uc3m_key,
    disclosable=["given_name", "final_grade"],        # selectively disclosable claims
    holder_jwk=holder.public_jwk(), vct=VCT)
print("\n2. Diploma issued as an SD-JWT VC (vct:", VCT + ")")
print("   selectively disclosable:", "given_name, final_grade")

# --- 3. The student presents it to an employer, proving possession of the wallet key ----
presentation = suite.create_presentation(
    diploma, holder_key=holder, audience="https://empleador.example", nonce="n-9f2c")

# --- 4. The employer verifies the credential WITH the FNMT-anchored issuer key ----------
result = suite.verify(
    presentation, public_key_jwk=issuer_jwk,
    audience="https://empleador.example", nonce="n-9f2c",
    require_key_binding=True, expected_vct=VCT)
print("\n3. Employer verification")
print("   issuer      :", result.issuer)
print("   vct         :", result.vct)
print("   key_bound   :", result.key_bound)
print("   title       :", result.claims.get("title"))
print("   disclosed   :", {k: result.claims.get(k) for k in ("given_name", "final_grade")})
print("\nVerified end to end: FNMT-anchored issuer + SD-JWT VC + holder binding.")
