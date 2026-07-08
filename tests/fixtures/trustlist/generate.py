"""Generate deterministic-shape (spec-shaped) EU Trusted List fixtures for tests.

Not the live EU LOTL (which we cannot fetch offline and whose XAdES signature is
exercised by the [trustlist] extra's own recorded test). These are ETSI TS 119 612
-shaped documents with self-signed EC P-256 certs, committed as golden fixtures so
the parser + walk logic is pinned. Regenerate with this script if the shape needs
to change.
"""
import base64
import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

OUT = pathlib.Path("tests/fixtures/trustlist")
OUT.mkdir(parents=True, exist_ok=True)

_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)


def _cert(cn: str) -> tuple[x509.Certificate, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE).not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, cert.public_bytes(Encoding.DER)


def _b64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


commission, commission_der = _cert("EU Commission LOTL Signer (test)")
de_signer, de_signer_der = _cert("DE Trusted List Signer (test)")
ca_qc_1, ca_qc_1_der = _cert("Example TSP DE Qualified CA 1 (test)")
ca_qc_2, ca_qc_2_der = _cert("Example TSP DE Qualified CA 2 (test)")
eds_q, eds_q_der = _cert("Example TSP DE Qualified e-Delivery (test)")
qsealcd, qsealcd_der = _cert("Example TSP DE Remote QSealCD Mgmt (test)")

# commit the commission cert (the LOTL signer the caller pins) as PEM
(OUT / "commission.pem").write_bytes(commission.public_bytes(Encoding.PEM))

LOTL = f"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" \
xmlns:add="http://uri.etsi.org/02231/v2/additionaltypes#">
  <SchemeInformation>
    <TSLVersionIdentifier>6</TSLVersionIdentifier>
    <TSLSequenceNumber>42</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
    <SchemeOperatorName><Name xml:lang="en">European Commission</Name></SchemeOperatorName>
    <SchemeTerritory>EU</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
    <PointersToOtherTSL>
      <OtherTSLPointer>
        <ServiceDigitalIdentities>
          <ServiceDigitalIdentity>
            <DigitalId><X509Certificate>{_b64(de_signer_der)}</X509Certificate></DigitalId>
          </ServiceDigitalIdentity>
        </ServiceDigitalIdentities>
        <TSLLocation>https://tl.example.de/de-tl.xml</TSLLocation>
        <AdditionalInformation>
          <OtherInformation><SchemeTerritory>DE</SchemeTerritory></OtherInformation>
          <OtherInformation>\
<TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
          <OtherInformation><add:MimeType>application/vnd.etsi.tsl+xml</add:MimeType></OtherInformation>
        </AdditionalInformation>
      </OtherTSLPointer>
      <OtherTSLPointer>
        <ServiceDigitalIdentities>
          <ServiceDigitalIdentity>
            <DigitalId><X509Certificate>{_b64(commission_der)}</X509Certificate></DigitalId>
          </ServiceDigitalIdentity>
        </ServiceDigitalIdentities>
        <TSLLocation>https://ec.example/lotl-pivot.xml</TSLLocation>
        <AdditionalInformation>
          <OtherInformation>\
<TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType></OtherInformation>
        </AdditionalInformation>
      </OtherTSLPointer>
    </PointersToOtherTSL>
  </SchemeInformation>
</TrustServiceStatusList>
"""

DE_TL = f"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>6</TSLVersionIdentifier>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">Bundesnetzagentur</Name></SchemeOperatorName>
    <SchemeTerritory>DE</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation><TSPName><Name xml:lang="en">Example TSP DE</Name></TSPName></TSPInformation>
      <TSPServices>
        <TSPService><ServiceInformation>
          <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">QC CA (granted)</Name></ServiceName>
          <ServiceDigitalIdentity>
            <DigitalId><X509Certificate>{_b64(ca_qc_1_der)}</X509Certificate></DigitalId>
          </ServiceDigitalIdentity>
          <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
          <StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime>
        </ServiceInformation></TSPService>
        <TSPService><ServiceInformation>
          <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">QC CA (withdrawn)</Name></ServiceName>
          <ServiceDigitalIdentity>
            <DigitalId><X509Certificate>{_b64(ca_qc_2_der)}</X509Certificate></DigitalId>
          </ServiceDigitalIdentity>
          <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
          <StatusStartingTime>2026-06-01T00:00:00Z</StatusStartingTime>
        </ServiceInformation></TSPService>
        <TSPService><ServiceInformation>
          <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EDS/Q</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">Qualified e-delivery (granted)</Name></ServiceName>
          <ServiceDigitalIdentity>
            <DigitalId><X509Certificate>{_b64(eds_q_der)}</X509Certificate></DigitalId>
          </ServiceDigitalIdentity>
          <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
          <StatusStartingTime>2026-05-01T00:00:00Z</StatusStartingTime>
          <ServiceSupplyPoints>
            <ServiceSupplyPoint>https://eds.example.de/submit</ServiceSupplyPoint>
          </ServiceSupplyPoints>
        </ServiceInformation></TSPService>
        <TSPService><ServiceInformation>
          <ServiceTypeIdentifier>\
http://uri.etsi.org/TrstSvc/Svctype/RemoteQSealCDManagement/Q</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">Remote QSealCD management (granted)</Name></ServiceName>
          <ServiceDigitalIdentity>
            <DigitalId><X509Certificate>{_b64(qsealcd_der)}</X509Certificate></DigitalId>
          </ServiceDigitalIdentity>
          <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
          <StatusStartingTime>2026-05-01T00:00:00Z</StatusStartingTime>
        </ServiceInformation></TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
"""

(OUT / "eu-lotl.xml").write_text(LOTL)
(OUT / "de-tl.xml").write_text(DE_TL)
print("wrote:", sorted(p.name for p in OUT.iterdir()))
print("ca_qc_1 sha256:", __import__("hashlib").sha256(ca_qc_1_der).hexdigest())
print("eds_q sha256:", __import__("hashlib").sha256(eds_q_der).hexdigest())
