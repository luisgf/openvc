"""
tests/test_openid4vci_vectors.py — OpenID4VCI pinned against material we did not write
(issue #147, ADR-0007 D10).

`tests/test_openid4vci.py` mints every proof it verifies, so it proves only that openvc
agrees with itself — the failure mode `tests/fixtures/trustlist/real/README.md` records
from the trusted-list work. These hold the same code to:

  * the **spec's own** OpenID4VCI 1.0 examples — App. F.1's `jwt` proof, which is a real
    ES256 signature and verifies end to end under a frozen clock, the three §8.2
    Credential Request bodies (a truncated single proof, a two-proof batch, and a `di_vp`
    proof whose elements are objects rather than strings), and App. D's key attestation
    with the attested-key proof that indexes it;
  * **recorded artifacts** from the EU reference issuer (`eudi-srv-web-issuing-eudiw-py`
    at `https://issuer.eudiw.dev`): its Issuer Metadata and two Credential Offers, in the
    deep-link form a wallet receives them.

What is still self-made is stated in `tests/fixtures/openid4vci/README.md`: no proof here
came from a shipping wallet, because obtaining one needs a live Credential Endpoint this
library does not ship.

Offline and deterministic — the one signed vector is verified at its own `iat`, so the
fixed bytes stay verifiable forever. Self-contained (tests/ is not a package).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import urllib.parse
from pathlib import Path

import pytest

from openvc.keys import jwk_thumbprint
from openvc.openid4vci import (
    DEFAULT_PROOF_MAX_AGE_S,
    CredentialRequestMalformed,
    UnsupportedProofType,
    parse_credential_request,
    peek_key_attestation,
    verify_credential_request_proofs,
)
from openvc.proof.errors import ClaimsInvalid, MalformedToken, SignatureInvalid

FIX = Path(__file__).parent / "fixtures" / "openid4vci"
SPEC = FIX / "spec"
REAL = FIX / "real"


def _spec(name: str) -> dict:
    return json.loads((SPEC / f"{name}.json").read_text(encoding="utf-8"))


def _utc(epoch: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)


class _Nonces:
    """A single-use nonce store, the shape ConsumeNonce documents."""

    def __init__(self, *valid: str) -> None:
        self.unused = set(valid)
        self.calls: list[str] = []

    def consume(self, nonce: str) -> bool:
        self.calls.append(nonce)
        try:
            self.unused.remove(nonce)  # one operation — the `DELETE … RETURNING` shape
        except KeyError:
            return False
        return True


# --------------------------------------------------------------------------- #
# App. F.1 — the spec's own signed key proof
# --------------------------------------------------------------------------- #

# The proof's own `iat`: 2023-12-07T09:27:24Z. Frozen here because the signed bytes are
# fixed and cannot be re-minted fresher.
F1_IAT = 1701960444
F1_ISSUER = "https://credential-issuer.example.com"
F1_NONCE = "LarRGSbmUPYtRYO6BQ4yn8"


def _f1_request() -> dict:
    return {
        "credential_configuration_id": "UniversityDegree",
        "proofs": _spec("proof-f.1-jwt")["proofs"],
    }


def test_spec_f1_proof_verifies_end_to_end():
    """The published App. F.1 example verifies — signature, aud, iat and nonce."""
    store = _Nonces(F1_NONCE)
    (proof,) = verify_credential_request_proofs(
        _f1_request(),
        credential_issuer=F1_ISSUER,
        check_nonce=store.consume,
        now=_utc(F1_IAT),
    )
    assert proof.alg == "ES256"
    assert proof.key_source == "jwk"
    assert proof.issued_at == F1_IAT
    assert proof.nonce == F1_NONCE
    assert proof.client_id is None
    assert proof.key_attestation is None
    assert proof.header["typ"] == "openid4vci-proof+jwt"
    assert proof.claims == {"aud": F1_ISSUER, "iat": F1_IAT, "nonce": F1_NONCE}
    # The key the credential would be bound to, and F.1's decoded header verbatim.
    assert proof.public_jwk == {
        "kty": "EC",
        "crv": "P-256",
        "x": "nUWAoAv3XZith8E7i19OdaxOLYFOwM-Z2EuM02TirT4",
        "y": "HskHU8BjUi1U9Xqi7Swmj8gwAK_0xkcDjEW_71SosEY",
    }
    assert proof.thumbprint == jwk_thumbprint(proof.public_jwk)
    # Consumed exactly once, and only after the signature verified.
    assert store.calls == [F1_NONCE]


def test_spec_f1_proof_is_stale_outside_the_freshness_window():
    """The same bytes, an hour later: rejected, and the nonce is *not* burned."""
    store = _Nonces(F1_NONCE)
    with pytest.raises(ClaimsInvalid):
        verify_credential_request_proofs(
            _f1_request(),
            credential_issuer=F1_ISSUER,
            check_nonce=store.consume,
            now=_utc(F1_IAT + DEFAULT_PROOF_MAX_AGE_S + 3600),
        )
    assert store.calls == []


def test_spec_f1_proof_rejects_a_different_credential_issuer():
    """`aud` is the anti-relay binding: the recorded proof is for one issuer only."""
    store = _Nonces(F1_NONCE)
    with pytest.raises(ClaimsInvalid):
        verify_credential_request_proofs(
            _f1_request(),
            credential_issuer="https://issuer.example.org",
            check_nonce=store.consume,
            now=_utc(F1_IAT),
        )
    assert store.calls == []


# --------------------------------------------------------------------------- #
# App. D — key attestations, and the proof that indexes one
# --------------------------------------------------------------------------- #

# The proof example's own `iat`: 2022-07-30T02:12:04Z.
APP_D_IAT = 1659145924
APP_D_ISSUER = "https://server.example.com"


def _compact(header: dict, claims: dict) -> str:
    """Re-encode a decoded spec example as a compact JWS with a meaningless signature.

    The spec prints these examples decoded, so there is nothing signed to transcribe.
    That the signature is nonsense is exactly what App. D reading must tolerate.
    """
    def seg(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{seg(header)}.{seg(claims)}.{base64.urlsafe_b64encode(b'0' * 64).decode()}"


def test_spec_app_d_key_attestation_is_read_without_being_verified():
    """Every member App. D defines, off the spec's own example, signature ignored."""
    example = _spec("key-attestation-app-d")["attestation"]
    peeked = peek_key_attestation(_compact(example["header"], example["claims"]))

    assert peeked.attested_keys == tuple(example["claims"]["attested_keys"])
    assert peeked.key_storage == ("iso_18045_moderate",)
    assert peeked.user_authentication == ("iso_18045_moderate",)
    assert (peeked.issued_at, peeked.expires_at) == (1516247022, 1541493724)
    assert peeked.certification is None and peeked.nonce is None and peeked.status is None
    # `typ` and the truncated placeholder `x5c` are exposed, not judged: pinning them is
    # a verifier's job, and that verifier needs a wallet-provider anchor openvc has none.
    assert peeked.header["typ"] == "key-attestation+jwt"
    assert peeked.header["x5c"] == ["MIIDQjCCA..."]


def test_spec_app_d_attested_proof_resolves_its_kid_as_an_index():
    """The spec's `kid: "0"` names a position in `attested_keys` — the caller's rule.

    Which is why openvc does not resolve it: nothing normative says an index is what a
    `kid` means here. What is pinned is that a caller who knows its ecosystem gets the
    material to apply that rule, and that the App. D binding then accepts the pairing —
    only the (meaningless) signature fails.
    """
    example = _spec("key-attestation-app-d")
    attestation = _compact(example["attestation"]["header"], example["attestation"]["claims"])
    header = dict(example["proof"]["header"], key_attestation=attestation)
    proof = _compact(header, example["proof"]["claims"])

    seen: list = []

    def resolve(ctx):
        seen.append(ctx)
        return ctx.key_attestation.attested_keys[int(ctx.kid)]

    with pytest.raises(SignatureInvalid):
        verify_credential_request_proofs(
            {"credential_configuration_id": "UniversityDegree", "proofs": {"jwt": [proof]}},
            credential_issuer=APP_D_ISSUER,
            check_nonce=lambda nonce: True,
            resolve_proof_key_in_context=resolve,
            now=_utc(APP_D_IAT),
        )

    (ctx,) = seen
    assert ctx.kid == "0" and ctx.alg == "ES256" and ctx.index == 0
    assert ctx.key_attestation.attested_keys[0] == \
        example["attestation"]["claims"]["attested_keys"][0]


def test_spec_app_d_binding_rejects_a_proof_key_the_attestation_does_not_carry():
    """App. D's MUST, against the spec's own attestation: a stranger's key is refused."""
    example = _spec("key-attestation-app-d")
    attestation = _compact(example["attestation"]["header"], example["attestation"]["claims"])
    header = dict(example["proof"]["header"], key_attestation=attestation)
    proof = _compact(header, example["proof"]["claims"])
    f1_header = _spec("proof-f.1-jwt")["proofs"]["jwt"][0].split(".")[0]
    stranger_jwk = json.loads(base64.urlsafe_b64decode(f1_header + "=="))["jwk"]

    with pytest.raises(ClaimsInvalid, match="not among the key attestation"):
        verify_credential_request_proofs(
            {"credential_configuration_id": "UniversityDegree", "proofs": {"jwt": [proof]}},
            credential_issuer=APP_D_ISSUER,
            check_nonce=lambda nonce: True,
            resolve_proof_key_in_context=lambda ctx: stranger_jwk,
            now=_utc(APP_D_IAT),
        )


# --------------------------------------------------------------------------- #
# §8.2 — the Credential Request wire contract
# --------------------------------------------------------------------------- #


def test_spec_8_2_minimal_request_shape():
    request = parse_credential_request(_spec("request-8.2-mdl-jwt-proof")["request"])
    assert request.credential_configuration_id == "org.iso.18013.5.1.mDL"
    assert request.credential_identifier is None
    assert request.proof_type == "jwt"
    assert len(request.proofs) == 1


def test_spec_8_2_truncated_proof_fails_as_a_malformed_token():
    """The spec truncates its proof to a bare header — a shape pin, not a signature."""
    with pytest.raises(MalformedToken):
        verify_credential_request_proofs(
            _spec("request-8.2-mdl-jwt-proof")["request"],
            credential_issuer="https://server.example.com",
            check_nonce=lambda nonce: True,
            now=_utc(F1_IAT),
        )


def test_spec_8_2_two_proof_batch_requires_opting_in():
    """An issuer that publishes no `batch_credential_issuance` accepts one proof."""
    body = _spec("request-8.2-degree-two-jwt-proofs")["request"]
    with pytest.raises(CredentialRequestMalformed):
        parse_credential_request(body)

    request = parse_credential_request(body, batch_size=2)
    assert request.credential_identifier == "CivilEngineeringDegree-2023"
    assert request.credential_configuration_id is None
    assert len(request.proofs) == 2


def test_spec_8_2_di_vp_is_unsupported_not_malformed():
    """`di_vp` elements are JSON objects (§8.2, App. F.2), which is legal but not ours.

    ADR-0007 leaves `di_vp` out; the contract is that it says so. Reporting it as a
    malformed request would tell a Credential Endpoint the wallet sent garbage when it
    sent a valid proof of a type we decline.
    """
    body = _spec("request-8.2-degree-di-vp-proof")["request"]
    assert list(body["proofs"]) == ["di_vp"]
    assert isinstance(body["proofs"]["di_vp"][0], dict)

    with pytest.raises(UnsupportedProofType):
        parse_credential_request(body)
    with pytest.raises(UnsupportedProofType):
        verify_credential_request_proofs(
            body,
            credential_issuer="https://server.example.com",
            check_nonce=lambda nonce: True,
            now=_utc(F1_IAT),
        )


# --------------------------------------------------------------------------- #
# Recorded from the EU reference issuer
# --------------------------------------------------------------------------- #


def _offer_from_uri(name: str) -> tuple[str, dict]:
    """Decode a Credential Offer deep link the way a wallet has to."""
    raw = (REAL / name).read_text(encoding="utf-8").strip()
    parsed = urllib.parse.urlsplit(raw)
    # The issuer emits `<scheme>://credential_offer?…`, so the well-known part lands in
    # the authority, not the path — a wallet that only reads `.path` finds nothing.
    assert (parsed.netloc or parsed.path.lstrip("/")) == "credential_offer", raw
    (encoded,) = urllib.parse.parse_qs(parsed.query)["credential_offer"]
    return parsed.scheme, json.loads(encoded)


def test_real_credential_offer_single_credential():
    scheme, offer = _offer_from_uri("eudiw-offer-pid-sd-jwt.uri")
    assert scheme == "haip-vci"
    assert offer["credential_issuer"] == "https://issuer.eudiw.dev"
    assert offer["credential_configuration_ids"] == ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
    assert set(offer["grants"]) == {"authorization_code"}
    assert offer["grants"]["authorization_code"]["issuer_state"]


def test_real_credential_offer_two_credentials():
    """The plural case, and the registered scheme rather than the HAIP one."""
    scheme, offer = _offer_from_uri("eudiw-offer-pid-mdl.uri")
    assert scheme == "openid-credential-offer"
    assert offer["credential_configuration_ids"] == [
        "eu.europa.ec.eudi.pid_vc_sd_jwt",
        "eu.europa.ec.eudi.mdl_mdoc",
    ]
    assert offer["credential_issuer"] == "https://issuer.eudiw.dev"


def test_real_issuer_metadata_is_the_shape_a_parser_must_survive():
    metadata = json.loads((REAL / "eudiw-issuer-metadata.json").read_text(encoding="utf-8"))
    assert metadata["credential_issuer"] == "https://issuer.eudiw.dev"
    assert metadata["credential_endpoint"] == "https://backend.issuer.eudiw.dev/credential"
    # OID4VCI 1.0 moved c_nonce minting to its own endpoint; the deployment publishes it.
    assert metadata["nonce_endpoint"] == "https://backend.issuer.eudiw.dev/nonce"

    configs = metadata["credential_configurations_supported"]
    assert len(configs) >= 27
    assert {c["format"] for c in configs.values()} == {"mso_mdoc", "dc+sd-jwt"}

    pid = configs["eu.europa.ec.eudi.pid_vc_sd_jwt"]
    assert pid["vct"] == "urn:eudi:pid:1"
    # Both proof types the ecosystem asks for, with an attestation requirement attached;
    # openvc verifies `jwt` and captures key attestations unverified (ADR-0007).
    assert set(pid["proof_types_supported"]) == {"jwt", "attestation"}
    assert pid["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"] == ["ES256"]


def test_real_issuer_batch_size_is_what_the_verifier_is_given():
    """`batch_credential_issuance.batch_size` is the caller's source for `batch_size`.

    openvc caps a batch at 1 unless told otherwise; this is where a real issuer's number
    comes from, and it is well above the two-proof §8.2 example.
    """
    metadata = json.loads((REAL / "eudiw-issuer-metadata.json").read_text(encoding="utf-8"))
    batch_size = metadata["batch_credential_issuance"]["batch_size"]
    assert batch_size == 100

    request = parse_credential_request(
        _spec("request-8.2-degree-two-jwt-proofs")["request"], batch_size=batch_size
    )
    assert len(request.proofs) == 2


def test_recorded_artifacts_match_their_documented_digests():
    """Provenance is enforced, not decorative: the README's sha256 column is the pin."""
    readme = (FIX / "README.md").read_text(encoding="utf-8")
    documented = dict(
        re.findall(r"^\| `([^`]+)` \|.*\| `([0-9a-f]{64})` \|$", readme, re.MULTILINE)
    )
    recorded = sorted(p.name for p in REAL.iterdir())
    assert recorded and sorted(documented) == recorded

    for name, digest in documented.items():
        assert hashlib.sha256((REAL / name).read_bytes()).hexdigest() == digest, name
