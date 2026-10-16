"""
tests/test_rp_registration_real_artifacts.py — four WRPRC producers, five real tokens
(``openvc.rp_registration``, issue #134).

#89 shipped the WRPRC module against self-made vectors plus the unsigned Annex C payload,
because no signed third-party WRPRC existed. These five do: genuine ES256 compact JWS
tokens minted by software this repository did not write, vendored byte-for-byte under
``tests/fixtures/rp_registration/`` (provenance, licences and digests in its
``PROVENANCE.md`` and ``NOTICE.md``).

**What this evidence is, and is not.** The tokens are *third-party-signed*; they are NOT
*registrar-anchored*. None comes from a Member State production registrar and none
chains to a LoTE anchor: every one is verified here against its OWN root (a pinned,
self-signed certificate), which proves the signature and the profile parse — not that
any real registrar vouched for anyone. #134's end-to-end goal, verifying a WRPRC against
the issuing registrar's *published* anchors, therefore stays open, and so does the CWT
form (no CWT exists, and TS 119 152-1 allocates no claim keys). These are PROVISIONAL
goldens: they settle what the producers emit, and nothing more.

They settled the three judgement calls #89 had to make (pinned below):

* ``intermediary.sname`` is what producers emit, never ``name``; ``intermediary.sub`` and
  ``act.sub`` are emitted *together* and agree;
* no token carries a JWS header ``iat``;
* ``crit`` appears, with ``["sigT", "b64"]``, on the Hopae registrar's tokens — which is
  why this lane understands those two names (and only those; the other lanes still
  refuse them, ``test_jws_crit.py``).

Every ``now`` is pinned to :data:`_NOW`, inside all five certificate windows; nothing
here reads the wall clock, so it cannot rot. ``tests/`` is not a package: nothing is
imported from a sibling test module.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from openvc.rp_registration import (
    RpRegistrationError,
    check_request_within_registration,
    parse_rp_registration_certificate,
    verify_rp_registration_certificate,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "rp_registration"
_NOW = dt.datetime(2026, 10, 16, 12, 0, tzinfo=dt.timezone.utc)
_UTC = dt.timezone.utc
_SERVICE_PROVIDER = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
# the lane's own refusal of a malformed sigT, not just any message that names the field
_SIG_T_REFUSED = r"header 'sigT' (must be an RFC 3339 UTC time|.* is not a valid UTC time)"


# --------------------------------------------------------------------------- #
# the vendored bytes — a silent edit must fail
# --------------------------------------------------------------------------- #

#: SHA-256 of every file under ``tests/fixtures/rp_registration`` except the two prose
#: files that describe them. Re-deriving a digest here is the point: PROVENANCE.md quotes
#: the same values, and ``test_provenance_quotes_every_digest`` checks the two agree.
_DIGESTS = {
    "german-sandbox/german-sandbox-wrprc.jwt":
        "4fed10eacaa2349da3ab6122b66064421042c20a06db27799061b8925a0a772f",
    "german-sandbox/german-sandbox-registrar-root.pem":
        "d955c23dc172db423abfd216578ddf84d66fb9df04986f85df15b6dab7ee7d83",
    "hopae-dev/wrprc.jwt":
        "e77bc0afed1914e98cf4d7ddcfe9f4a6453897f2ed79c9bc9a454a672a102e0b",
    "hopae-dev/wrprc_intermediated.jwt":
        "5c4233504b475b934da088b388f24adaf6bff706cc723f5c6172ee426f072377",
    "digg/registration_certificate.jwt":
        "8e593fcdf05f22b8d2d028f16ba4703bd2135e50a87bab5127ac95d84eabd0aa",
    "digg/registration_certificate.jwt.license":
        "80b9cadc15d92cb6838d1e2da47f069464b79d53e4e6a1ff3e9e70e090848ea9",
    "eudi-verifier-endpoint/wrprc.jwt":
        "128a731d54c04eab1e4f7aeeba35104d1835137a1c1c4c7d8a8c04d6473da74f",
    "LICENSES/BSD-2-Clause.SUNET-vc.md":
        "f2877a81ccd055186daf9b690f2fad786583ff64832cdeb8ca3e5ed4d3ad7194",
    "LICENSES/Apache-2.0.axle.txt":
        "c4b4a1bc54721eb916e05b8471da8c11184c752507b905c76ff330a08bfdc65f",
    "LICENSES/Apache-2.0.eudi-srv-verifier-endpoint.txt":
        "30251107b55133e6090ac2ef94d7d925cddfbb7fbe5301793739f52ac3c59f20",
    "LICENSES/CC0-1.0.txt":
        "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499",
}


@pytest.mark.parametrize("relpath", sorted(_DIGESTS))
def test_vendored_file_is_byte_identical(relpath: str) -> None:
    data = (_FIXTURES / relpath).read_bytes()
    assert hashlib.sha256(data).hexdigest() == _DIGESTS[relpath], (
        f"{relpath} no longer matches the vendored bytes (PROVENANCE.md); a third-party "
        f"artifact is recorded, not edited")


def test_nothing_unlisted_is_vendored() -> None:
    # A new file dropped in the directory must be a decision: pinned here, described in
    # PROVENANCE.md, licensed in NOTICE.md.
    on_disk = {p.relative_to(_FIXTURES).as_posix()
               for p in _FIXTURES.rglob("*") if p.is_file()}
    assert on_disk == set(_DIGESTS) | {"PROVENANCE.md", "NOTICE.md"}


def test_provenance_quotes_every_digest() -> None:
    text = (_FIXTURES / "PROVENANCE.md").read_text(encoding="utf-8")
    missing = [rel for rel, digest in _DIGESTS.items() if digest not in text]
    assert not missing, f"PROVENANCE.md does not quote the SHA-256 of {missing}"


def test_provenance_states_the_limits_of_the_evidence() -> None:
    # The honesty claim travels with the files, not only with this docstring.
    text = (_FIXTURES / "PROVENANCE.md").read_text(encoding="utf-8").lower()
    for phrase in ("not registrar-anchored", "provisional", "#134"):
        assert phrase in text, f"PROVENANCE.md lost its statement: {phrase!r}"


# --------------------------------------------------------------------------- #
# the five tokens, each with its own pinned root
# --------------------------------------------------------------------------- #

def _read_token(relpath: str) -> str:
    return (_FIXTURES / relpath).read_bytes().decode("ascii").strip()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _header(token: str) -> dict[str, Any]:
    return json.loads(_unb64url(token.split(".")[0]))


def _payload(token: str) -> dict[str, Any]:
    return json.loads(_unb64url(token.split(".")[1]))


def _x5c_cert(token: str, index: int) -> x509.Certificate:
    return x509.load_der_x509_certificate(base64.b64decode(_header(token)["x5c"][index]))


def _der_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@dataclasses.dataclass(frozen=True)
class Artifact:
    """One vendored token and the root it is verified against."""
    name: str
    relpath: str
    anchor: Callable[[str], x509.Certificate]
    anchor_sha256: str                    # SHA-256 of the anchor certificate's DER


def _german_root(_token: str) -> x509.Certificate:
    pem = (_FIXTURES / "german-sandbox" / "german-sandbox-registrar-root.pem").read_bytes()
    return x509.load_pem_x509_certificate(pem)


ARTIFACTS = [
    Artifact("german-sandbox", "german-sandbox/german-sandbox-wrprc.jwt", _german_root,
             "7421221cb1da97b3edb4ad2ccb4d00cbdced1e1316bf6768e677218cdb246d3e"),
    Artifact("hopae", "hopae-dev/wrprc.jwt", lambda t: _x5c_cert(t, 0),
             "0f138b93443b0b6dda73e3a1914c0e3b7d02469e70d9d02d7c83934ca4466d10"),
    Artifact("hopae-intermediated", "hopae-dev/wrprc_intermediated.jwt",
             lambda t: _x5c_cert(t, 0),
             "0f138b93443b0b6dda73e3a1914c0e3b7d02469e70d9d02d7c83934ca4466d10"),
    Artifact("digg", "digg/registration_certificate.jwt", lambda t: _x5c_cert(t, 1),
             "728112a9744640161b6bed7039db06001de5c07ab2a474bd0352f7fd3f97e198"),
    Artifact("eudi-verifier-endpoint", "eudi-verifier-endpoint/wrprc.jwt",
             lambda t: _x5c_cert(t, 0),
             "fa822676c43fd0647f885af6fb6147c8bbcc57bb39980d10250ff895ac532344"),
]
_BY_NAME = {a.name: a for a in ARTIFACTS}
_IDS = [a.name for a in ARTIFACTS]


def _token(name: str) -> str:
    return _read_token(_BY_NAME[name].relpath)


def _verify(name: str, token: str | None = None, **kwargs: Any):
    art = _BY_NAME[name]
    token = token if token is not None else _token(name)
    kwargs.setdefault("now", _NOW)
    kwargs.setdefault("trust_anchors", [art.anchor(_token(name))])
    return verify_rp_registration_certificate(token, **kwargs)


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_the_anchor_is_the_pinned_certificate(art: Artifact) -> None:
    # The anchor is a constant, not "whatever the token carries": taking x5c[0] out of a
    # token and trusting it would be circular, so its digest is pinned independently.
    assert _der_sha256(art.anchor(_token(art.name))) == art.anchor_sha256


def test_the_german_root_file_is_the_tokens_own_x5c_certificate() -> None:
    token = _token("german-sandbox")
    assert _der_sha256(_x5c_cert(token, 0)) == _der_sha256(_german_root(token))


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_every_certificate_window_contains_the_pinned_instant(art: Artifact) -> None:
    # If this fails the fixtures did not change: the calendar did. Move _NOW, or retire
    # the artifact — do not let the verification tests below fail with a trust error.
    token = _token(art.name)
    for index in range(len(_header(token)["x5c"])):
        cert = _x5c_cert(token, index)
        assert cert.not_valid_before_utc <= _NOW <= cert.not_valid_after_utc, (
            f"{art.name} x5c[{index}] is not valid at {_NOW.isoformat()}")


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_verifies_end_to_end_against_its_own_root(art: Artifact) -> None:
    reg = _verify(art.name)
    assert reg.form == "jwt"
    assert reg.entitlements and all(
        e.startswith("https://uri.etsi.org/19475/Entitlement/") for e in reg.entitlements)
    assert reg.subject_identifier is not None


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_parse_without_trust_reads_the_same_claims(art: Artifact) -> None:
    token = _token(art.name)
    assert parse_rp_registration_certificate(token).claims == _verify(art.name).claims
    assert _verify(art.name).claims == _payload(token)


# --------------------------------------------------------------------------- #
# the decoded facts — what real producers emit
# --------------------------------------------------------------------------- #

_FACTS = {
    # name: (sub, trade name, country, header parameters, payload iat or None)
    "german-sandbox": ("NTRDE-BD7070256AF93987", "Siros Foundation", "DE",
                       {"typ", "x5c", "alg"}, None),
    "hopae": ("VATLU-12345678", "Example Company", "LU",
              {"alg", "typ", "x5c", "x5t#S256", "sigT", "b64", "crit"}, 1783870343),
    "hopae-intermediated": ("VATLU-99998888", "Final RP", "LU",
                            {"alg", "typ", "x5c", "x5t#S256", "sigT", "b64", "crit"},
                            1783871409),
    "digg": ("VATSE-12345678", "DIGG Wallet Ecosystem", "SE",
             {"typ", "alg", "x5c"}, 1790680892),
    "eudi-verifier-endpoint": ("LEIEU-123456789", "Kotlin Issuer Signer Dev", "EU",
                               {"x5c", "typ", "alg"}, 1783681028),
}


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_decoded_identity_and_header_shape(art: Artifact) -> None:
    sub, name, country, header_params, iat = _FACTS[art.name]
    reg = _verify(art.name)
    assert reg.subject_identifier == sub
    assert reg.trade_name == name
    assert reg.country == country
    assert set(reg.header) == header_params
    assert reg.header["typ"] == "rc-wrp+jwt"
    assert reg.header["alg"] == "ES256"
    assert reg.issued_at == (None if iat is None
                             else dt.datetime.fromtimestamp(iat, tz=_UTC))


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_no_token_carries_a_jws_header_iat(art: Artifact) -> None:
    # #134's second judgement call. JAdES (TS 119 182-1 clause 5.1.11) mandates a header
    # `iat` for signatures after 2025-07-15, TS 119 475 Table 5 omits it: all five
    # producers follow Table 5. The header `iat` therefore stays surfaced, not required.
    assert "iat" not in _verify(art.name).header


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_every_signer_chain_is_one_or_two_certificates_ending_at_the_anchor(
        art: Artifact) -> None:
    token = _token(art.name)
    chain = _header(token)["x5c"]
    assert len(chain) == (2 if art.name == "digg" else 1)
    # the last certificate of the chain is the self-signed anchor, in all five
    assert _der_sha256(_x5c_cert(token, len(chain) - 1)) == art.anchor_sha256
    last = _x5c_cert(token, len(chain) - 1)
    assert last.subject == last.issuer


def test_the_signers_are_self_signed_cas_so_these_are_not_registrar_evidence() -> None:
    # Why these tokens are provisional goldens: the German and Hopae registrars sign
    # directly with a self-signed CA certificate (CA:TRUE, keyUsage keyCertSign|cRLSign,
    # no digitalSignature) that is also the anchor; the EU sample's "CN=test" carries no
    # extension at all. Only Digg has a leaf (CA:FALSE, digitalSignature) under a root.
    def basic_constraints(cert: x509.Certificate) -> x509.BasicConstraints | None:
        try:
            return cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            return None

    german = _x5c_cert(_token("german-sandbox"), 0)
    hopae = _x5c_cert(_token("hopae"), 0)
    digg_leaf = _x5c_cert(_token("digg"), 0)
    eu = _x5c_cert(_token("eudi-verifier-endpoint"), 0)

    for ca in (german, hopae):
        bc = basic_constraints(ca)
        assert bc is not None and bc.ca and bc.path_length == 0
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign and ku.crl_sign and not ku.digital_signature
        assert ca.subject == ca.issuer
    leaf_bc = basic_constraints(digg_leaf)
    assert leaf_bc is not None and not leaf_bc.ca
    assert digg_leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    assert eu.subject == eu.issuer and len(eu.extensions) == 0
    assert eu.subject.rfc4514_string() == "CN=test"


# ---- the intermediary / act spelling (#134, first judgement call) ---------- #

def test_the_intermediated_token_emits_sname_and_both_identifier_spellings() -> None:
    reg = _verify("hopae-intermediated")
    assert reg.intermediary == {"sub": "LEIXG-INTERMEDIARY01", "sname": "Mediator"}
    assert reg.claims["act"] == {"sub": "LEIXG-INTERMEDIARY01"}
    # the producer writes `sname` (Table 10), never the Annex C `name`
    assert reg.intermediary is not None and "name" not in reg.intermediary
    assert reg.intermediary_name == "Mediator"
    # `intermediary.sub` and `act.sub` are emitted TOGETHER and agree
    assert reg.intermediary_identifier == "LEIXG-INTERMEDIARY01"
    # Table 7 NOTE 2: `sub` stays the relying party, not the intermediary
    assert reg.subject_identifier == "VATLU-99998888"


@pytest.mark.parametrize("name", [n for n in _IDS if n != "hopae-intermediated"])
def test_no_other_token_is_intermediated(name: str) -> None:
    reg = _verify(name)
    assert reg.intermediary is None and "act" not in reg.claims
    assert reg.intermediary_identifier is None and reg.intermediary_name is None


def test_the_reader_still_accepts_both_spellings_the_producers_do_not_use() -> None:
    # The real artifacts say which spelling issuers emit; they do not retire the other,
    # which the specification itself uses (Annex C `name`). Unchanged by this work.
    reg = _verify("hopae-intermediated")
    claims = dict(reg.claims)
    claims["intermediary"] = {"name": "Annex C Name"}
    claims.pop("act")
    twin = dataclasses.replace(reg, claims=claims, intermediary=claims["intermediary"])
    assert twin.intermediary_name == "Annex C Name"
    assert twin.intermediary_identifier is None


# ---- crit / sigT / b64 (#134, third judgement call) ------------------------ #

@pytest.mark.parametrize("name", ["hopae", "hopae-intermediated"])
def test_the_hopae_header_lists_sigt_and_b64_as_critical(name: str) -> None:
    reg = _verify(name)
    assert reg.header["crit"] == ["sigT", "b64"]
    assert reg.header["b64"] is True
    # `x5t#S256` is the thumbprint of x5c[0] — the JAdES signing-certificate reference
    digest = hashlib.sha256(base64.b64decode(reg.header["x5c"][0])).digest()
    assert reg.header["x5t#S256"] == _b64url(digest)


@pytest.mark.parametrize("name", [n for n in _IDS if not n.startswith("hopae")])
def test_the_other_producers_emit_no_crit(name: str) -> None:
    assert "crit" not in _verify(name).header


@pytest.mark.parametrize("name, sigt, expected, iat", [
    ("hopae", "2026-07-12T15:32:23Z",
     dt.datetime(2026, 7, 12, 15, 32, 23, tzinfo=_UTC), 1783870343),
    ("hopae-intermediated", "2026-07-12T15:50:09Z",
     dt.datetime(2026, 7, 12, 15, 50, 9, tzinfo=_UTC), 1783871409),
])
def test_sigt_is_surfaced_and_equals_the_payload_iat(
        name: str, sigt: str, expected: dt.datetime, iat: int) -> None:
    reg = _verify(name)
    assert reg.header["sigT"] == sigt
    assert reg.claimed_signing_time == expected
    # The registrar writes the same instant twice (header sigT, payload iat). They stay
    # two fields: nothing reads sigT for validity, only the payload's `iat` does.
    assert reg.issued_at == dt.datetime.fromtimestamp(iat, tz=_UTC) == expected


@pytest.mark.parametrize("name", [n for n in _IDS if not n.startswith("hopae")])
def test_no_sigt_means_no_claimed_signing_time(name: str) -> None:
    assert _verify(name).claimed_signing_time is None


def test_sigt_is_signed_so_editing_it_breaks_the_signature() -> None:
    # sigT is in the protected header, hence covered by the registrar's signature: a
    # well-formed but different time is a signature failure, not a silent edit.
    token = _token("hopae")
    forged = _rewrite_header(token, lambda h: h.update(sigT="2026-07-12T15:32:24Z"))
    with pytest.raises(RpRegistrationError, match="signature verification failed"):
        _verify("hopae", forged)


# ---- srv_description: two shapes, no authorization effect (scope D) -------- #

@pytest.mark.parametrize("name, nested", [
    ("german-sandbox", True), ("hopae", True), ("hopae-intermediated", True),
    ("digg", False), ("eudi-verifier-endpoint", False),
])
def test_srv_description_is_nested_in_some_producers_and_flat_in_others(
        name: str, nested: bool) -> None:
    reg = _verify(name)
    raw = reg.claims["srv_description"]
    assert isinstance(raw, list) and raw
    if nested:
        assert all(isinstance(item, list) for item in raw)      # [[{lang, value}]]
    else:
        assert all(isinstance(item, dict) for item in raw)      # [{lang, value}]
    # either way the typed view is the same flat tuple of {lang, value} objects
    assert reg.service_description
    assert all(set(item) == {"lang", "value"} for item in reg.service_description)


def test_srv_description_is_display_text_with_no_authorization_effect() -> None:
    # The scope check reads `credentials` only. Blank or replace the display text and
    # the verdict, for a request that passes and for one that fails, does not move.
    reg = _verify("german-sandbox")
    allowed = _query("dc+sd-jwt", {"vct_values": ["eu.europa.ec.eudi.pid.1"]},
                     [["family_name"]])
    denied = _query("dc+sd-jwt", {"vct_values": ["eu.europa.ec.eudi.pid.1"]},
                    [["document_number"]])
    for text in ((), ({"lang": "en", "value": "Totally Different Service"},),
                 ({"lang": "xx", "value": ""}, {"value": 3})):
        twin = dataclasses.replace(reg, service_description=text)
        check_request_within_registration(twin, allowed)
        with pytest.raises(RpRegistrationError, match="does not register"):
            check_request_within_registration(twin, denied)


def test_digg_service_identifier_is_not_a_typed_field() -> None:
    # Digg adds `service_identifier`; TS 119 475 defines none and the #89 reading has no
    # service id. It stays available verbatim in `claims`, with no typed attribute.
    reg = _verify("digg")
    assert reg.claims["service_identifier"] == "wallet-ecosystem"
    assert not hasattr(reg, "service_identifier")


# ---- temporal facts -------------------------------------------------------- #

def test_german_and_hopae_and_eu_have_no_exp_and_digg_has_a_365_day_one() -> None:
    for name in ("german-sandbox", "hopae", "hopae-intermediated", "eudi-verifier-endpoint"):
        assert _verify(name).expires_at is None            # `exp` is optional (Table 10)
    digg = _verify("digg")
    assert digg.issued_at == dt.datetime(2026, 9, 29, 11, 21, 32, tzinfo=_UTC)
    assert digg.expires_at is not None
    assert digg.expires_at - digg.issued_at == dt.timedelta(days=365)  # within GEN-5.2.4-08


def test_the_german_token_has_neither_iat_nor_exp() -> None:
    reg = _verify("german-sandbox")
    assert reg.issued_at is None and reg.expires_at is None
    assert "iat" not in reg.claims and "exp" not in reg.claims
    with pytest.raises(RpRegistrationError, match="no 'exp'"):
        _verify("german-sandbox", require_expiry=True)


def test_digg_is_refused_once_expired() -> None:
    after = dt.datetime.fromtimestamp(1822216892 + 3600, tz=_UTC)
    with pytest.raises(RpRegistrationError, match="expired"):
        _verify("digg", now=after)


@pytest.mark.parametrize("name, when", [
    ("german-sandbox", dt.datetime(2028, 2, 1, tzinfo=_UTC)),            # after 2028-01-16
    ("hopae", dt.datetime(2026, 7, 1, tzinfo=_UTC)),                     # before 2026-07-12
    ("digg", dt.datetime(2026, 9, 1, tzinfo=_UTC)),                      # leaf from 09-29
    ("eudi-verifier-endpoint", dt.datetime(2027, 8, 1, tzinfo=_UTC)),    # after 2027-07-10
])
def test_a_certificate_outside_its_validity_window_does_not_validate(
        name: str, when: dt.datetime) -> None:
    with pytest.raises(RpRegistrationError, match="did not validate to a trust anchor"):
        _verify(name, now=when)


# --------------------------------------------------------------------------- #
# controls — the real signatures are doing the work
# --------------------------------------------------------------------------- #

def _rewrite_header(token: str, mutate: Callable[[dict[str, Any]], Any]) -> str:
    """Re-encode the header after *mutate*, keeping the original payload and signature —
    so the signature no longer matches and any error that is NOT a signature failure
    came from a check that runs before the crypto."""
    head, payload, sig = token.split(".")
    header = json.loads(_unb64url(head))
    mutate(header)
    new_head = _b64url(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_head}.{payload}.{sig}"


def _flip_one_payload_byte(token: str) -> str:
    """Change ONE byte of the payload, inside a JSON string value so it stays valid JSON,
    and keep the original signature."""
    head, payload, sig = token.split(".")
    raw = bytearray(_unb64url(payload))
    needle = _payload(token)["name"].encode()
    at = bytes(raw).index(needle)
    raw[at] = ord("Z") if raw[at] != ord("Z") else ord("Y")
    return f"{head}.{_b64url(bytes(raw))}.{sig}"


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_one_flipped_payload_byte_is_a_signature_failure(art: Artifact) -> None:
    token = _token(art.name)
    tampered = _flip_one_payload_byte(token)
    assert tampered != token and len(tampered) == len(token)
    # it still parses — the failure is the signature's, not a decoding accident
    assert parse_rp_registration_certificate(tampered).form == "jwt"
    with pytest.raises(RpRegistrationError, match="signature verification failed"):
        _verify(art.name, tampered)


@pytest.mark.parametrize("art", ARTIFACTS, ids=_IDS)
def test_one_flipped_signature_byte_is_a_signature_failure(art: Artifact) -> None:
    head, payload, sig = _token(art.name).split(".")
    raw = bytearray(_unb64url(sig))
    raw[0] ^= 0x01
    with pytest.raises(RpRegistrationError, match="signature"):
        _verify(art.name, f"{head}.{payload}.{_b64url(bytes(raw))}")


# every (token, root of a different CA) pair; both Hopae tokens share one CA, so they
# are not a wrong-anchor pair for each other
_WRONG_ANCHOR_PAIRS = [
    (signer, other) for signer in _IDS for other in _IDS
    if _BY_NAME[signer].anchor_sha256 != _BY_NAME[other].anchor_sha256
]


@pytest.mark.parametrize("signer, anchor_of", _WRONG_ANCHOR_PAIRS)
def test_another_producers_root_is_not_a_trust_anchor(signer: str, anchor_of: str) -> None:
    wrong = _BY_NAME[anchor_of].anchor(_token(anchor_of))
    with pytest.raises(RpRegistrationError, match="did not validate to a trust anchor"):
        _verify(signer, trust_anchors=[wrong])


def test_no_anchor_at_all_is_refused_before_anything_is_trusted() -> None:
    with pytest.raises(RpRegistrationError, match="no trust anchors"):
        _verify("hopae", trust_anchors=[])


# ---- the envelope still fails closed on a real token ----------------------- #
# Each edit leaves the genuine signature in place, which no longer matches: so the
# error must name the check that fired BEFORE any crypto, not "signature".

@pytest.mark.parametrize("alg", ["none", "None", "HS256", "RS256", "PS256", "ES512", "", None, 7])
def test_alg_outside_the_allow_list_is_refused_before_crypto(alg: Any) -> None:
    forged = _rewrite_header(_token("hopae"), lambda h: h.update(alg=alg))
    with pytest.raises(RpRegistrationError, match="not permitted"):
        _verify("hopae", forged)


def test_an_unknown_critical_name_is_refused_even_beside_the_two_understood_ones() -> None:
    forged = _rewrite_header(_token("hopae"), lambda h: h.update(
        crit=["sigT", "b64", "exp"], exp=4102444800))
    with pytest.raises(RpRegistrationError, match="critical"):
        _verify("hopae", forged)


@pytest.mark.parametrize("crit", [
    ["sigT", "b64", "sigD"],
    ["sigT", "sigT"],
    ["b64", "b64"],
    ["sigT", "b64", "sigT"],
    ["sigT", "b64", "kid"],
    [],
    "sigT",
    ["sigT", 1],
    {"sigT": True},
    None,
])
def test_a_hostile_crit_is_refused_before_crypto(crit: Any) -> None:
    forged = _rewrite_header(_token("hopae"), lambda h: h.update(crit=crit, sigD={}, kid="k"))
    with pytest.raises(RpRegistrationError) as exc:
        _verify("hopae", forged)
    assert "signature" not in str(exc.value)


def test_a_critical_name_missing_from_the_header_is_refused() -> None:
    forged = _rewrite_header(_token("hopae"), lambda h: h.pop("sigT"))
    with pytest.raises(RpRegistrationError, match="not present"):
        _verify("hopae", forged)


@pytest.mark.parametrize("b64", [False, "true", "false", 1, 0, None, [], {}, [True]])
def test_b64_other_than_the_json_boolean_true_is_refused(b64: Any) -> None:
    forged = _rewrite_header(_token("hopae"), lambda h: h.update(b64=b64))
    with pytest.raises(RpRegistrationError, match="JSON boolean true"):
        _verify("hopae", forged)


@pytest.mark.parametrize("b64", [False, "true", 1, None])
def test_b64_is_checked_even_when_crit_does_not_name_it(b64: Any) -> None:
    # A token that sets `b64: false` and says nothing in `crit` is read as an unencoded
    # payload by a verifier that honours the parameter and as base64url by this one: a
    # parser differential, refused wherever the value appears.
    forged = _rewrite_header(_token("german-sandbox"), lambda h: h.update(b64=b64))
    with pytest.raises(RpRegistrationError, match="JSON boolean true"):
        _verify("german-sandbox", forged)


@pytest.mark.parametrize("sigt", [
    "", "2026-07-12", "2026-07-12T15:32:23", "2026-07-12T15:32:23+00:00",
    "2026-07-12t15:32:23z", "2026-07-12 15:32:23Z", "2026-07-12T15:32:23Z\n",
    "2026-13-12T15:32:23Z", "2026-02-30T15:32:23Z", "2026-07-12T24:00:00Z",
    "2026-07-12T15:32:60Z", "0000-01-01T00:00:00Z", "2026-07-12T15:32:23.Z",
    "١٤٤٤-07-12T15:32:23Z",                    # Arabic-Indic digits: \d would take them
    1783870343, 1783870343.0, True, None, [], {},
])
def test_sigt_that_is_not_an_rfc_3339_utc_time_is_refused(sigt: Any) -> None:
    forged = _rewrite_header(_token("hopae"), lambda h: h.update(sigT=sigt))
    with pytest.raises(RpRegistrationError, match=_SIG_T_REFUSED):
        _verify("hopae", forged)


def test_sigt_is_checked_even_when_crit_does_not_name_it() -> None:
    forged = _rewrite_header(_token("german-sandbox"), lambda h: h.update(sigT="yesterday"))
    with pytest.raises(RpRegistrationError, match=_SIG_T_REFUSED):
        _verify("german-sandbox", forged)


def test_the_bmi_profile_and_a_missing_chain_are_still_named() -> None:
    bmi = _rewrite_header(_token("digg"), lambda h: h.update(typ="rc-rp+jwt"))
    with pytest.raises(RpRegistrationError, match="German BMI"):
        _verify("digg", bmi)
    bare = _rewrite_header(_token("digg"), lambda h: h.pop("x5c"))
    with pytest.raises(RpRegistrationError, match="no 'x5c'"):
        _verify("digg", bare)


# ---- the authorization cross-check on registered scope --------------------- #

def _query(fmt: str, meta: dict[str, Any] | None,
           paths: list[list[Any]] | None) -> dict[str, Any]:
    entry: dict[str, Any] = {"id": "q", "format": fmt}
    if meta is not None:
        entry["meta"] = meta
    if paths is not None:
        entry["claims"] = [{"path": p} for p in paths]
    return {"credentials": [entry]}


def test_the_german_grant_covers_what_it_lists_and_nothing_else() -> None:
    reg = _verify("german-sandbox")
    meta = {"vct_values": ["eu.europa.ec.eudi.pid.1"]}
    check_request_within_registration(
        reg, _query("dc+sd-jwt", meta, [["family_name"], ["given_name"], ["birth_date"]]))
    for bad in ([["document_number"]], [["family_name"], ["address", "locality"]]):
        with pytest.raises(RpRegistrationError, match="does not register"):
            check_request_within_registration(reg, _query("dc+sd-jwt", meta, bad))
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(
            reg, _query("dc+sd-jwt", {"vct_values": ["urn:eudi:pid:1"]}, [["family_name"]]))
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(
            reg, _query("mso_mdoc", {"doctype_value": "eu.europa.ec.eudi.pid.1"},
                        [["eu.europa.ec.eudi.pid.1", "family_name"]]))
    with pytest.raises(RpRegistrationError, match="names no claims"):
        check_request_within_registration(reg, _query("dc+sd-jwt", meta, None))


def test_the_digg_grant_registers_address_members_not_the_address_container() -> None:
    reg = _verify("digg")
    meta = {"vct_values": ["urn:eudi:pid:1"]}
    check_request_within_registration(reg, _query(
        "dc+sd-jwt", meta, [["family_name"], ["address", "locality"], ["address", "country"]]))
    # Asking for the whole `address` object asks for members that were not registered
    # one by one (a registered path must be a prefix of the requested one, not longer).
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(reg, _query("dc+sd-jwt", meta, [["address"]]))
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(
            reg, _query("dc+sd-jwt", meta, [["address", "region"]]))
    check_request_within_registration(
        reg, _query("dc+sd-jwt", meta, [["birthdate"]]), intended_use_id="1")
    with pytest.raises(RpRegistrationError, match="intended use"):
        check_request_within_registration(
            reg, _query("dc+sd-jwt", meta, [["birthdate"]]), intended_use_id="2")


@pytest.mark.parametrize("name", ["hopae", "hopae-intermediated"])
def test_a_registration_entry_without_claim_paths_grants_nothing(name: str) -> None:
    # The Hopae `credentials` entry lists a format and a `meta` but no `claim`: an
    # incomplete registration, which the fail-closed reading (#152) must not turn into a
    # blanket entitlement. Held up against the producer's own output.
    reg = _verify(name)
    if name == "hopae":
        assert [c.format for c in reg.credentials] == ["dc+sd-jwt"]
        assert all(c.claim_paths == () for c in reg.credentials)
        meta = {"vct_values": ["urn:eudi:pid:de:1"]}
        with pytest.raises(RpRegistrationError, match="does not register"):
            check_request_within_registration(reg, _query("dc+sd-jwt", meta, [["family_name"]]))
        with pytest.raises(RpRegistrationError, match="names no claims"):
            check_request_within_registration(reg, _query("dc+sd-jwt", meta, None))
    else:
        assert reg.credentials == ()                    # a payload with no `credentials`
        with pytest.raises(RpRegistrationError, match="does not register"):
            check_request_within_registration(
                reg, _query("dc+sd-jwt", {"vct_values": ["urn:eudi:pid:1"]}, [["x"]]))


def test_a_provider_wrprc_registers_provided_attestations_not_requestable_credentials() -> None:
    # The EU sample describes an issuer: `provides_attestations`, no `credentials`. It
    # authorizes nothing as a *requester*, however many entitlements it lists.
    reg = _verify("eudi-verifier-endpoint")
    assert reg.credentials == ()
    assert [p.format for p in reg.provides_attestations] == ["dc+sd-jwt", "mso_mdoc", "mso_mdoc"]
    assert len(reg.entitlements) == 3
    with pytest.raises(RpRegistrationError, match="does not register"):
        check_request_within_registration(
            reg, _query("dc+sd-jwt", {"vct_values": ["urn:eudi:pid:1"]}, [["family_name"]]))


def test_the_entitlement_floor_holds_on_real_tokens() -> None:
    for name in _IDS:
        assert any(e.startswith("https://uri.etsi.org/19475/Entitlement/")
                   for e in _verify(name).entitlements)
    assert _verify("german-sandbox").entitlements == (_SERVICE_PROVIDER,)
