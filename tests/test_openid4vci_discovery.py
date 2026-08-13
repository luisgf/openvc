"""
tests/test_openid4vci_discovery.py — the OID4VCI 1.0 discovery parsers (issue #142).

`parse_credential_offer` (§4.1.1) and `parse_credential_issuer_metadata` (§11.2.3)
parse **untrusted third-party JSON** — what a wallet receives, or what an issuer
checking its own deployment reads back. The pinned contract is fail-closed:

  * `credential_issuer` must be an absolute **https** URL — it is the identifier the
    key proof's `aud` is compared against, so a malformed one must never reach the
    verifier;
  * endpoint URLs in metadata must be https and absolute, `authorization_servers` a
    non-empty array of them;
  * `credential_configuration_ids` must be a non-empty array of distinct non-empty
    strings;
  * unknown `grants` members are **preserved, not dropped** — a caller must see what
    it chose not to support;
  * hostile input (deep nesting, wrong types, empties) raises a typed error, never an
    uncaught one, and never gets silently narrowed.

Happy paths run against material we did not write: the spec's own §4.1.1/§11.2.3
examples and the recorded EU-reference-issuer artifacts from #147
(`tests/fixtures/openid4vci/`). Self-contained (tests/ is not a package).
"""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest

from openvc.openid4vci import (
    GRANT_AUTHORIZATION_CODE,
    GRANT_PRE_AUTHORIZED_CODE,
    CredentialOfferMalformed,
    IssuerMetadataMalformed,
    parse_credential_issuer_metadata,
    parse_credential_offer,
)

FIX = Path(__file__).parent / "fixtures" / "openid4vci"
SPEC = FIX / "spec"
REAL = FIX / "real"


def _spec(name: str) -> dict:
    return json.loads((SPEC / f"{name}.json").read_text(encoding="utf-8"))


def _offer_from_uri(name: str) -> dict:
    """Decode a recorded Credential Offer deep link the way a wallet has to."""
    raw = (REAL / name).read_text(encoding="utf-8").strip()
    (encoded,) = urllib.parse.parse_qs(urllib.parse.urlsplit(raw).query)[
        "credential_offer"]
    return json.loads(encoded)


# --------------------------------------------------------------------------- #
# Happy paths — the spec's own examples
# --------------------------------------------------------------------------- #


def test_spec_offer_pre_authorized_code_example():
    """§4.1.1's pre-authorized example: two ids, the tx_code block kept in `grants`."""
    offer = parse_credential_offer(_spec("offer-4.1.1-pre-authorized")["offer"])
    assert offer.credential_issuer == "https://credential-issuer.example.com"
    assert offer.credential_configuration_ids == (
        "UniversityDegreeCredential", "org.iso.18013.5.1.mDL")
    assert list(offer.grants) == [GRANT_PRE_AUTHORIZED_CODE]
    grant = offer.grants[GRANT_PRE_AUTHORIZED_CODE]
    assert grant["pre-authorized_code"] == "oaKazRN8I0IbtZ0C7JuMn5"
    assert grant["tx_code"]["length"] == 4
    assert offer.raw["grants"] is not offer.grants  # the grants view is a copy


def test_spec_offer_authorization_code_example():
    """§4.1.2's authorization-code example: `issuer_state` is opaque and survives."""
    offer = parse_credential_offer(_spec("offer-4.1.1-authorization-code")["offer"])
    assert offer.credential_configuration_ids == ("UniversityDegreeCredential",)
    assert list(offer.grants) == [GRANT_AUTHORIZATION_CODE]
    assert offer.grants[GRANT_AUTHORIZATION_CODE]["issuer_state"].startswith(
        "eyJhbGciOiJSU0Et")


def test_spec_issuer_metadata_example():
    """§11.2.3's example: every endpoint, the batch size, the extension points kept."""
    metadata = parse_credential_issuer_metadata(
        _spec("issuer-metadata-11.2.3")["metadata"])
    assert metadata.credential_issuer == "https://credential-issuer.example.com"
    assert metadata.credential_endpoint == \
        "https://credential-issuer.example.com/credential"
    assert metadata.authorization_servers == ("https://server.example.com",)
    assert metadata.nonce_endpoint == "https://credential-issuer.example.com/nonce"
    assert metadata.deferred_credential_endpoint == \
        "https://credential-issuer.example.com/deferred_credential"
    assert metadata.notification_endpoint == \
        "https://credential-issuer.example.com/notification"
    assert metadata.batch_size == 10
    # The extension points are narrowed by nothing: display, both encryption blocks,
    # and the per-configuration shapes reach the caller untouched.
    assert "SD_JWT_VC_example_in_OpenID4VCI" in metadata.credential_configurations_supported
    assert metadata.raw["credential_request_encryption"]["encryption_required"] is True
    assert metadata.raw["display"][1]["locale"] == "fr-FR"


# --------------------------------------------------------------------------- #
# Happy paths — recorded from the EU reference issuer (#147 fixtures)
# --------------------------------------------------------------------------- #


def test_real_offer_single_credential():
    offer = parse_credential_offer(_offer_from_uri("eudiw-offer-pid-sd-jwt.uri"))
    assert offer.credential_issuer == "https://issuer.eudiw.dev"
    assert offer.credential_configuration_ids == ("eu.europa.ec.eudi.pid_vc_sd_jwt",)
    assert list(offer.grants) == [GRANT_AUTHORIZATION_CODE]
    assert offer.grants[GRANT_AUTHORIZATION_CODE]["issuer_state"]


def test_real_offer_two_credentials():
    offer = parse_credential_offer(_offer_from_uri("eudiw-offer-pid-mdl.uri"))
    assert offer.credential_configuration_ids == (
        "eu.europa.ec.eudi.pid_vc_sd_jwt", "eu.europa.ec.eudi.mdl_mdoc")


def test_real_offer_parses_straight_from_the_query_string():
    """A JSON string is accepted as-is — no caller-side `json.loads` required."""
    raw = (REAL / "eudiw-offer-pid-sd-jwt.uri").read_text(encoding="utf-8").strip()
    (encoded,) = urllib.parse.parse_qs(urllib.parse.urlsplit(raw).query)[
        "credential_offer"]
    offer = parse_credential_offer(encoded)
    assert offer.credential_issuer == "https://issuer.eudiw.dev"


def test_real_issuer_metadata():
    """The recorded 91 KB deployment document, through the parser."""
    metadata = parse_credential_issuer_metadata(
        json.loads((REAL / "eudiw-issuer-metadata.json").read_text(encoding="utf-8")))
    assert metadata.credential_issuer == "https://issuer.eudiw.dev"
    assert metadata.credential_endpoint == "https://backend.issuer.eudiw.dev/credential"
    assert metadata.nonce_endpoint == "https://backend.issuer.eudiw.dev/nonce"
    assert metadata.deferred_credential_endpoint is not None
    assert metadata.notification_endpoint is not None
    # The deployment publishes no `authorization_servers`: optional means absent.
    assert metadata.authorization_servers == ()
    assert metadata.batch_size == 100
    # 27 real credential configurations, narrowed by nothing.
    assert len(metadata.credential_configurations_supported) >= 27
    pid = metadata.credential_configurations_supported["eu.europa.ec.eudi.pid_vc_sd_jwt"]
    assert pid["format"] == "dc+sd-jwt"


# --------------------------------------------------------------------------- #
# Credential Offer — the fail-closed corpus
# --------------------------------------------------------------------------- #


class TestCredentialOfferMalformed:
    def test_not_an_object(self):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer(["https://issuer.example"])
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer(42)

    def test_invalid_json_string(self):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer("{not json")
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer('["https://issuer.example"]')

    def test_hostile_deep_nesting(self):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer("[" * 100_000)

    def test_missing_credential_issuer(self):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer({"credential_configuration_ids": ["Degree"]})

    @pytest.mark.parametrize("issuer", [
        "http://issuer.example",                 # downgrade smuggle
        "//issuer.example",                      # no scheme
        "issuer.example",                        # not absolute
        "https://",                              # no host
        "",                                      # empty
        42,                                      # wrong type
        # Adversarial-review regressions (the identifier compares byte-for-byte
        # against a signed `aud`, so nothing that parses differently downstream
        # may survive here):
        "https://[::1",                          # urlparse raises — must stay typed
        "https://issuer.example:notaport",       # port raises lazily — force it here
        "https://issuer.example:99999",          # port out of range
        "https://\tissuer.example",              # urlparse strips \t\r\n silently
        "https:// issuer.example",               # whitespace
        "https://issuer.example\x00",            # control characters
        "https://legit.example@evil.example",    # userinfo: identifier vs connection
        "https://user:pass@issuer.example",      # credentials would leak into logs
        "https://issuer.example#fragment",       # not part of an identifier
        "https://issuer.example?query=1",        # not part of an identifier
        "https://.",                             # no usable host
    ])
    def test_credential_issuer_must_be_an_absolute_https_url(self, issuer):
        """The issuer identifier feeds the key proof's `aud` check — fail closed."""
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer({
                "credential_issuer": issuer,
                "credential_configuration_ids": ["Degree"]})

    def test_missing_configuration_ids(self):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer({"credential_issuer": "https://issuer.example"})

    @pytest.mark.parametrize("ids", [
        [],                                      # empty array
        "",                                      # not an array
        "Degree",                                # a bare string
        [""],                                    # empty entry
        [None],                                  # wrong type
        ["Degree", "Degree"],                    # duplicates are ambiguous
    ])
    def test_configuration_ids_must_be_distinct_non_empty_strings(self, ids):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ids})

    def test_grants_must_be_an_object(self):
        with pytest.raises(CredentialOfferMalformed):
            parse_credential_offer({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["Degree"],
                "grants": "authorization_code"})

    def test_grants_is_optional(self):
        offer = parse_credential_offer({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["Degree"]})
        assert offer.grants == {}

    def test_unknown_grant_members_are_preserved(self):
        """A grant type openvc does not know must still reach the caller."""
        offer = parse_credential_offer({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["Degree"],
            "grants": {"com.example.custom-grant": {"token": "abc"}}})
        assert offer.grants["com.example.custom-grant"] == {"token": "abc"}

    def test_unknown_top_level_members_survive_in_raw(self):
        offer = parse_credential_offer({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["Degree"],
            "grants": {},
            "credential_offer_uri": "https://issuer.example/offer/123"})
        assert offer.raw["credential_offer_uri"] == "https://issuer.example/offer/123"


# --------------------------------------------------------------------------- #
# Issuer Metadata — the fail-closed corpus
# --------------------------------------------------------------------------- #

_BASE_METADATA = {
    "credential_issuer": "https://issuer.example",
    "credential_endpoint": "https://issuer.example/credential",
}


class TestIssuerMetadataMalformed:
    def test_not_an_object(self):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata("[]")
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata(None)

    def test_invalid_json_string(self):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata("{nope")

    def test_hostile_deep_nesting(self):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata("[" * 100_000)

    @pytest.mark.parametrize("member", ["credential_issuer", "credential_endpoint"])
    def test_required_members(self, member):
        body = {k: v for k, v in _BASE_METADATA.items() if k != member}
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata(body)

    @pytest.mark.parametrize("member", ["credential_issuer", "credential_endpoint"])
    @pytest.mark.parametrize("url", [
        "http://issuer.example", "//issuer.example", "issuer.example", "https://", 42,
        "https://[::1",                          # urlparse raises — must stay typed
        "https://issuer.example:notaport",       # lazy port ValueError, forced here
        "https://\tissuer.example",              # silently stripped control chars
        "https://legit.example@evil.example",    # userinfo spoofing
        "https://issuer.example#fragment",
    ])
    def test_required_members_must_be_absolute_https(self, member, url):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata({**_BASE_METADATA, member: url})

    @pytest.mark.parametrize("member", [
        "nonce_endpoint", "deferred_credential_endpoint", "notification_endpoint",
    ])
    @pytest.mark.parametrize("url", [
        "http://issuer.example", "issuer.example", 42,
        "https://[]",                            # urlparse raises — must stay typed
        "https://a@b.example",                   # userinfo
        "https://issuer.example:99999",          # lazy port ValueError, forced here
    ])
    def test_optional_endpoints_must_be_https_when_present(self, member, url):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata({**_BASE_METADATA, member: url})

    @pytest.mark.parametrize("member", [
        "nonce_endpoint", "deferred_credential_endpoint", "notification_endpoint",
    ])
    def test_optional_endpoints_are_optional(self, member):
        metadata = parse_credential_issuer_metadata(_BASE_METADATA)
        assert getattr(metadata, member) is None

    @pytest.mark.parametrize("servers", [
        "https://as.example",                    # not an array
        [],                                      # empty array
        ["http://as.example"],                   # non-https entry
        [42],                                    # wrong type
    ])
    def test_authorization_servers_must_be_https_urls(self, servers):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata(
                {**_BASE_METADATA, "authorization_servers": servers})

    def test_authorization_servers_is_optional(self):
        metadata = parse_credential_issuer_metadata(_BASE_METADATA)
        assert metadata.authorization_servers == ()

    def test_configurations_supported_must_be_an_object(self):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata(
                {**_BASE_METADATA, "credential_configurations_supported": ["Degree"]})

    def test_configurations_supported_is_optional(self):
        metadata = parse_credential_issuer_metadata(_BASE_METADATA)
        assert metadata.credential_configurations_supported == {}

    @pytest.mark.parametrize("batch", [
        "100",                                   # not an object
        {},                                      # no batch_size
        {"batch_size": "100"},                   # wrong type
        {"batch_size": 1},                       # a batch of one is not a batch
        {"batch_size": 0},
        {"batch_size": True},                    # bool is not an int
    ])
    def test_batch_credential_issuance_shape(self, batch):
        with pytest.raises(IssuerMetadataMalformed):
            parse_credential_issuer_metadata(
                {**_BASE_METADATA, "batch_credential_issuance": batch})

    def test_batch_credential_issuance_is_optional(self):
        metadata = parse_credential_issuer_metadata(_BASE_METADATA)
        assert metadata.batch_size is None

    def test_unknown_members_survive_in_raw(self):
        metadata = parse_credential_issuer_metadata(
            {**_BASE_METADATA, "signed_metadata": "eyJhbGci...",
             "display": [{"name": "Issuer"}]})
        assert metadata.raw["signed_metadata"] == "eyJhbGci..."
        assert metadata.raw["display"] == [{"name": "Issuer"}]
