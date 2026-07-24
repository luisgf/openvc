"""
tests/test_jwk_thumbprint.py — RFC 7638 JWK Thumbprint (issue #140).

Pins:
  * the two published golden vectors — RFC 7638 §3.1 (RSA) and RFC 8037 §2 (OKP
    Ed25519). These are real spec output, not shapes we also produce.
  * the *exclusion* property: only the required members per `kty` are digested, so
    `kid`/`use`/`alg` are ignored and a private key hashes identically to its public
    half. RFC 7638's own example carries `alg` and `kid`, which is what makes it a
    test of exclusion and not just of hashing.
  * canonical-form ordering: insertion order of the input mapping cannot change the
    digest.
  * every fail-closed path — unknown/missing/non-string `kty`, a missing or
    non-string required member, an unsupported hash.

Wire values are copied verbatim from the RFCs.
"""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from openvc.keys import (
    Ed25519SigningKey,
    InvalidKey,
    P256SigningKey,
    P384SigningKey,
    jwk_thumbprint,
    jwk_thumbprint_bytes,
)

# RFC 7638 §3.1 — the worked example, verbatim (note `alg` and `kid` are present and
# must NOT affect the digest).
RFC7638_RSA_JWK = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
         "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn"
         "64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz"
         "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08"
         "qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1"
         "jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_RSA_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

# RFC 8037 §2 — the Ed25519 public JWK and its published thumbprint, plus the private
# JWK from the same section (same key, so the same thumbprint).
RFC8037_OKP_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}
RFC8037_OKP_PRIVATE_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}
RFC8037_OKP_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ------------------------------------------------------------------ golden vectors #

def test_rfc7638_rsa_worked_example_matches_the_published_thumbprint():
    assert jwk_thumbprint(RFC7638_RSA_JWK) == RFC7638_RSA_THUMBPRINT


def test_rfc8037_ed25519_example_matches_the_published_thumbprint():
    assert jwk_thumbprint(RFC8037_OKP_JWK) == RFC8037_OKP_THUMBPRINT


def test_bytes_and_string_forms_agree():
    raw = jwk_thumbprint_bytes(RFC8037_OKP_JWK)
    assert len(raw) == 32
    assert _b64url(raw) == RFC8037_OKP_THUMBPRINT


# --------------------------------------------------------------------- exclusion #

def test_optional_members_do_not_change_the_digest():
    """RFC 7638's own vector carries `alg` and `kid`; stripping them must not move it."""
    bare = {k: v for k, v in RFC7638_RSA_JWK.items() if k in ("kty", "n", "e")}
    assert jwk_thumbprint(bare) == RFC7638_RSA_THUMBPRINT


def test_private_okp_key_hashes_identically_to_its_public_half():
    assert jwk_thumbprint(RFC8037_OKP_PRIVATE_JWK) == RFC8037_OKP_THUMBPRINT


@pytest.mark.parametrize("factory", [
    lambda: P256SigningKey.generate(kid="k"),
    lambda: P384SigningKey.generate(kid="k"),
    lambda: Ed25519SigningKey.generate(kid="k"),
])
def test_private_members_never_reach_the_digest(factory):
    """A `d` (and friends) smuggled into a public JWK cannot change its thumbprint."""
    public = factory().public_jwk()
    contaminated = dict(public, d="AAAA", p="BBBB", q="CCCC", kid="other", use="sig")
    assert jwk_thumbprint(contaminated) == jwk_thumbprint(public)


def test_unknown_members_are_ignored_rather_than_digested():
    extended = dict(RFC8037_OKP_JWK, x5c=["ignored"], nonsense_member="ignored")
    assert jwk_thumbprint(extended) == RFC8037_OKP_THUMBPRINT


# ---------------------------------------------------------------- canonical form #

def test_input_ordering_does_not_change_the_digest():
    forward = {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_OKP_JWK["x"]}
    reverse = {"x": RFC8037_OKP_JWK["x"], "crv": "Ed25519", "kty": "OKP"}
    assert jwk_thumbprint(forward) == jwk_thumbprint(reverse) == RFC8037_OKP_THUMBPRINT


def test_ec_canonical_form_is_crv_kty_x_y_with_no_whitespace():
    """Pin the EC member set and ordering against a hand-built canonical form."""
    jwk = P256SigningKey.generate(kid="k").public_jwk()
    canonical = (
        '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}'
        % (jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
    )
    expected = _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())
    assert jwk_thumbprint(jwk) == expected


def test_okp_canonical_form_omits_y():
    jwk = Ed25519SigningKey.generate(kid="k").public_jwk()
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        sort_keys=True, separators=(",", ":"))
    expected = _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())
    assert jwk_thumbprint(jwk) == expected


def test_distinct_keys_get_distinct_thumbprints():
    a = P256SigningKey.generate(kid="k").public_jwk()
    b = P256SigningKey.generate(kid="k").public_jwk()
    assert jwk_thumbprint(a) != jwk_thumbprint(b)


def test_same_coordinates_under_a_different_curve_do_not_collide():
    """`crv` is inside the canonical form, so it separates otherwise-equal members."""
    jwk = Ed25519SigningKey.generate(kid="k").public_jwk()
    assert jwk_thumbprint(jwk) != jwk_thumbprint(dict(jwk, crv="X25519"))


# ------------------------------------------------------------------- hash choice #

@pytest.mark.parametrize("hash_name,size", [
    ("sha-256", 32), ("sha-384", 48), ("sha-512", 64)])
def test_supported_hashes_produce_their_digest_size(hash_name, size):
    assert len(jwk_thumbprint_bytes(RFC8037_OKP_JWK, hash_name=hash_name)) == size


def test_a_stronger_hash_changes_the_thumbprint():
    assert (jwk_thumbprint(RFC8037_OKP_JWK, hash_name="sha-512")
            != RFC8037_OKP_THUMBPRINT)


def test_unsupported_hash_is_rejected():
    with pytest.raises(InvalidKey, match="unsupported thumbprint hash"):
        jwk_thumbprint(RFC8037_OKP_JWK, hash_name="md5")


# ------------------------------------------------------------------- fail closed #

@pytest.mark.parametrize("jwk", [
    {},                                             # no kty at all
    {"kty": None, "x": "AAAA"},                     # non-string kty
    {"kty": 256, "x": "AAAA"},                      # numeric kty
])
def test_missing_or_non_string_kty_is_rejected(jwk):
    with pytest.raises(InvalidKey, match="no string 'kty'"):
        jwk_thumbprint(jwk)


@pytest.mark.parametrize("kty", ["", "ec", "EC2", "unknown", "AKP"])
def test_unsupported_kty_is_rejected(kty):
    with pytest.raises(InvalidKey, match="unsupported JWK kty"):
        jwk_thumbprint({"kty": kty, "crv": "P-256", "x": "AAAA", "y": "BBBB"})


@pytest.mark.parametrize("missing", ["crv", "x", "y"])
def test_ec_missing_a_required_member_is_rejected(missing):
    jwk = P256SigningKey.generate(kid="k").public_jwk()
    del jwk[missing]
    with pytest.raises(InvalidKey, match="needs a string"):
        jwk_thumbprint(jwk)


def test_okp_missing_crv_is_rejected():
    with pytest.raises(InvalidKey, match="needs a string"):
        jwk_thumbprint({"kty": "OKP", "x": RFC8037_OKP_JWK["x"]})


@pytest.mark.parametrize("value", [None, 42, b"bytes", ["list"], {"a": 1}, True])
def test_non_string_required_member_is_rejected(value):
    """A partial or oddly-typed key must never be silently coerced into a digest."""
    with pytest.raises(InvalidKey, match="needs a string"):
        jwk_thumbprint(dict(RFC8037_OKP_JWK, x=value))


def test_rsa_missing_exponent_is_rejected():
    with pytest.raises(InvalidKey, match="needs a string"):
        jwk_thumbprint({"kty": "RSA", "n": RFC7638_RSA_JWK["n"]})


# ------------------------------------------------------------------ integration #

def test_round_trips_through_every_software_backend():
    """Every backend's public_jwk() is thumbprintable — no backend emits a shape the
    canonical form cannot express."""
    for key in (
        Ed25519SigningKey(ed25519.Ed25519PrivateKey.generate(), kid="k"),
        P256SigningKey(ec.generate_private_key(ec.SECP256R1()), kid="k"),
        P384SigningKey(ec.generate_private_key(ec.SECP384R1()), kid="k"),
    ):
        assert len(jwk_thumbprint(key.public_jwk())) == 43   # 32 bytes, b64url unpadded


def test_key_agreement_public_jwk_is_thumbprintable():
    """P256KeyAgreementKey tags its JWK with use='enc'; that must not leak in."""
    from openvc.keys import P256KeyAgreementKey

    agreement = P256KeyAgreementKey.generate(kid="k")
    jwk = agreement.public_jwk()
    assert jwk.get("use") == "enc"
    bare = {k: v for k, v in jwk.items() if k in ("kty", "crv", "x", "y")}
    assert jwk_thumbprint(jwk) == jwk_thumbprint(bare)
