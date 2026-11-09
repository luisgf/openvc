"""
tests/test_openid4vci_canonical_jwk.py — the OpenID4VCI proof key in canonical form
(issues #379 and #401, audit of 2026-11-07 § M2 / § L12).

RFC 7638 digests the JWK member *strings*; the base64url decoder behind the signature
check is tolerant (an explicit `=`, a non-alphabet character, the standard alphabet,
non-zero trailing bits all decode to the same coordinate, and a leading zero octet
decodes to the same integer). One key therefore had many spellings that verified alike
and thumbprinted apart, so a batch deduplicated by thumbprint accepted N spellings of
one key as N keys, and every per-key policy downstream could be walked around the same
way. The header `jwk` also came back verbatim, `x5u` URLs and all, and was signed into
`cnf.jwk` on the documented path.

Pinned here (maintainer decision D9 — strict on the proof key, canonical minimal form
downstream):

  * the header `jwk` is the **strict** side: a padded, dirty-bit, non-alphabet or
    wrong-width coordinate is `ClaimsInvalid` naming the member, before any crypto;
  * a batch of spellings is refused as non-canonical, before the duplicate rule;
  * `VerifiedProof.public_jwk` has exactly the RFC 7638 members and `thumbprint` is of
    that form; a resolver's key is normalised rather than refused;
  * App. D's `attested_keys` are compared in canonical form, so an attestation that
    spells an honest key non-canonically still matches — and a wrong-width one still
    refuses, naming RFC 7518 §6.2.1.2;
  * `openvc.keys.canonical_public_jwk`, the helper behind all of it — including, from
    the adversarial review of the PR, that an Ed25519 `x` must be a canonical point
    encoding of a point that is not small-order (the identity had four "canonical"
    spellings and signs for anyone), that every attested key is read before any is
    matched, and the helper's own contract on junk input and message bounds.

The `openvc.keys` helper is imported inside its tests on purpose: against a tree that
predates it the behavioural tests must still be collected and fail on their own merits.
Proofs are minted locally with offline keys. Self-contained (tests/ is not a package).
"""
from __future__ import annotations

import base64
import datetime as dt
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519

from openvc.keys import Ed25519SigningKey, P256SigningKey, P384SigningKey, jwk_thumbprint
from openvc.openid4vci import verify_credential_request_proofs
from openvc.proof._jws import sign_compact
from openvc.proof.errors import ClaimsInvalid, SignatureInvalid

ISSUER = "https://issuer.example"
NONCE = "c-nonce-abc123"
NOW = dt.datetime(2026, 7, 24, 12, 0, tzinfo=dt.timezone.utc)
NOW_TS = int(NOW.timestamp())

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_UNSET = object()


# --------------------------------------------------------------------------- helpers #

def _proof(key, *, jwk=None, key_param="jwk", header_extra=None, signer=None):
    header = {"typ": "openid4vci-proof+jwt", "alg": key.alg}
    if key_param == "jwk":
        header["jwk"] = key.public_jwk() if jwk is None else jwk
    elif key_param == "kid":
        header["kid"] = "wallet-key-1"
    header.update(header_extra or {})
    claims = {"aud": ISSUER, "iat": NOW_TS, "nonce": NONCE}
    return sign_compact(header, claims, signing_key=signer or key)


def _attestation(*jwks, attested_keys=_UNSET):
    """An App. D key attestation signed by a throwaway nobody ever verifies."""
    claims = {"iss": "https://wallet-provider.example", "iat": NOW_TS, "exp": NOW_TS + 3600}
    claims["attested_keys"] = list(jwks) if attested_keys is _UNSET else attested_keys
    provider = P256SigningKey.generate(kid="wallet-provider")
    return sign_compact({"typ": "key-attestation+jwt", "alg": provider.alg}, claims,
                        signing_key=provider)


def _request(*proofs):
    return {"credential_configuration_id": "UniversityDegree", "proofs": {"jwt": list(proofs)}}


def _verify(body, **kw):
    kw.setdefault("credential_issuer", ISSUER)
    kw.setdefault("check_nonce", lambda n: True)
    kw.setdefault("now", NOW)
    return verify_credential_request_proofs(body, **kw)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _raw(segment: str) -> bytes:
    """The tolerant decode the signature path uses — what an attacker gets to exploit."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


# The spellings. Each one decodes to the SAME bytes as the canonical member (asserted in
# the tests that use them), which is what made the thumbprint the wrong identity.
def _padded(segment: str) -> str:
    return segment + "="


def _non_alphabet(segment: str) -> str:
    return segment + "!="           # the decoder drops '!' and then accepts the '='


def _dirty_bits(segment: str) -> str:
    """Non-zero trailing bits. Only a 43-character (32-byte) member has 2 slack bits."""
    assert len(segment) == 43
    index = _ALPHABET.index(segment[-1])
    assert index & 0x03 == 0, "a canonical member has zero trailing bits"
    return segment[:-1] + _ALPHABET[(index & 0x3C) | 0x03]


def _wide(segment: str) -> str:
    """A leading zero octet: the same integer, one byte too many (RFC 7518 §6.2.1.2)."""
    return _b64u(b"\x00" + _raw(segment))


def _off_curve(jwk: dict) -> dict:
    raw = bytearray(_raw(jwk["y"]))
    raw[-1] ^= 0x01
    return dict(jwk, y=_b64u(bytes(raw)))


_P256 = lambda: P256SigningKey.generate(kid="w")          # noqa: E731
_P384 = lambda: P384SigningKey.generate(kid="w")          # noqa: E731
_ED = lambda: Ed25519SigningKey.generate(kid="w")         # noqa: E731
_ED_RFC9864 = lambda: Ed25519SigningKey.generate(kid="w", alg="Ed25519")   # noqa: E731

_NOT_CANONICAL_X = r"key proof jwk: JWK member\(s\) \['x'\] are not canonical base64url"
_NOT_CANONICAL_Y = r"key proof jwk: JWK member\(s\) \['y'\] are not canonical base64url"


# ---------------------------------------------- the header jwk is the strict side #

@pytest.mark.parametrize("factory", [_P256, _P384, _ED, _ED_RFC9864])
def test_a_padded_x_is_refused_naming_the_member(factory):
    key = factory()
    canonical = key.public_jwk()
    spelled = dict(canonical, x=_padded(canonical["x"]))
    assert _raw(spelled["x"]) == _raw(canonical["x"])          # same key to the decoder
    assert jwk_thumbprint(spelled) != jwk_thumbprint(canonical)  # another key to RFC 7638

    with pytest.raises(ClaimsInvalid, match=_NOT_CANONICAL_X):
        _verify(_request(_proof(key, jwk=spelled)))


@pytest.mark.parametrize("factory, member", [(_P256, "y"), (_P256, "x"), (_ED, "x")])
def test_dirty_trailing_bits_are_refused_naming_the_member(factory, member):
    key = factory()
    canonical = key.public_jwk()
    spelled = dict(canonical, **{member: _dirty_bits(canonical[member])})
    assert _raw(spelled[member]) == _raw(canonical[member])
    assert spelled[member] != canonical[member]

    with pytest.raises(ClaimsInvalid, match=rf"\['{member}'\] are not canonical base64url"):
        _verify(_request(_proof(key, jwk=spelled)))


@pytest.mark.parametrize("factory", [_P256, _P384, _ED])
def test_a_non_alphabet_character_is_refused_naming_the_member(factory):
    key = factory()
    canonical = key.public_jwk()
    spelled = dict(canonical, x=_non_alphabet(canonical["x"]))
    assert _raw(spelled["x"]) == _raw(canonical["x"])

    with pytest.raises(ClaimsInvalid, match=_NOT_CANONICAL_X):
        _verify(_request(_proof(key, jwk=spelled)))


def test_the_standard_alphabet_is_refused_when_it_differs():
    """`+`/`/` decode like `-`/`_` under urlsafe_b64decode; RFC 7515 §2 says base64url."""
    while True:                                           # a key whose x has a '-' or '_'
        key = _P256()
        canonical = key.public_jwk()
        if "-" in canonical["x"] or "_" in canonical["x"]:
            break
    spelled = dict(canonical, x=canonical["x"].replace("-", "+").replace("_", "/"))
    assert _raw(spelled["x"]) == _raw(canonical["x"])

    with pytest.raises(ClaimsInvalid, match=_NOT_CANONICAL_X):
        _verify(_request(_proof(key, jwk=spelled)))


def test_every_non_canonical_member_is_named():
    key = _P256()
    canonical = key.public_jwk()
    spelled = dict(canonical, x=_padded(canonical["x"]), y=_non_alphabet(canonical["y"]))
    with pytest.raises(ClaimsInvalid, match=r"\['x', 'y'\] are not canonical"):
        _verify(_request(_proof(key, jwk=spelled)))


def test_the_refusal_names_the_member_and_never_echoes_its_value():
    key = _P256()
    canonical = key.public_jwk()
    spelled = dict(canonical, x=canonical["x"] + "!" * 3000 + "=")
    assert _raw(spelled["x"]) == _raw(canonical["x"])
    with pytest.raises(ClaimsInvalid, match=_NOT_CANONICAL_X) as info:
        _verify(_request(_proof(key, jwk=spelled)))
    assert "!!!" not in str(info.value) and len(str(info.value)) < 300


@pytest.mark.parametrize("factory, member", [(_P256, "x"), (_P256, "y"), (_P384, "x"), (_ED, "x")])
def test_a_coordinate_of_the_wrong_width_is_refused_citing_rfc_7518(factory, member):
    """A leading zero octet is the same integer to `int.from_bytes` — on the tree before
    this change such a proof verified AND thumbprinted as a different key."""
    key = factory()
    canonical = key.public_jwk()
    spelled = dict(canonical, **{member: _wide(canonical[member])})
    assert (int.from_bytes(_raw(spelled[member]), "big")
            == int.from_bytes(_raw(canonical[member]), "big"))

    with pytest.raises(ClaimsInvalid, match=rf"'{member}' must decode to the .*RFC 7518 §6.2.1.2"):
        _verify(_request(_proof(key, jwk=spelled)))


def test_an_off_curve_point_in_the_header_jwk_is_refused_before_any_crypto():
    """Structure before crypto: it was a SignatureInvalid out of the backend; now it is
    the key-shape refusal every other malformed jwk gets, and the store is never asked."""
    key = _P256()
    calls = []
    with pytest.raises(ClaimsInvalid, match="is not a valid P-256 public key"):
        _verify(_request(_proof(key, jwk=_off_curve(key.public_jwk()))),
                check_nonce=lambda n: calls.append(n) or True)
    assert calls == []


def test_the_canonical_check_runs_before_the_signature_and_before_the_nonce():
    """A padded jwk on a proof signed by someone else: the spelling wins over the signature,
    and the nonce store is never touched by a proof that did not verify."""
    key, forger = _P256(), _P256()
    spelled = dict(key.public_jwk(), x=_padded(key.public_jwk()["x"]))
    calls = []
    with pytest.raises(ClaimsInvalid, match=_NOT_CANONICAL_X):
        _verify(_request(_proof(key, jwk=spelled, signer=forger)),
                check_nonce=lambda n: calls.append(n) or True)
    assert calls == []


def test_private_members_and_the_alg_binding_are_still_judged_first():
    """The existing structure rules keep their messages; canonical form comes after them."""
    key = _P256()
    spelled = dict(key.public_jwk(), x=_padded(key.public_jwk()["x"]))
    with pytest.raises(ClaimsInvalid, match="private members"):
        _verify(_request(_proof(key, jwk=dict(spelled, d="c2VjcmV0"))))
    ed = _ED()
    with pytest.raises(ClaimsInvalid, match="needs a kty=EC crv=P-256"):
        _verify(_request(_proof(key, jwk=dict(ed.public_jwk(), x=_padded(ed.public_jwk()["x"])))))


@pytest.mark.parametrize("x", ["", "=", "====", "!!!!", "ü" * 43, "A" * 4000, None, 1, [], {},
                               "AAAA" * 10 + "A"],
                         ids=["empty", "pad", "pads", "bangs", "non-ascii", "4000-chars", "null",
                              "int", "list", "object", "41-chars"])
def test_junk_coordinates_never_escape_the_documented_taxonomy(x):
    """A 4000-character blob stays under the 16 KiB proof cap, so it reaches the key check
    (a larger one is `CredentialRequestMalformed` at the request shape, as documented)."""
    key = _P256()
    with pytest.raises(ClaimsInvalid):
        _verify(_request(_proof(key, jwk=dict(key.public_jwk(), x=x))))


# ---------------------------------------------------------------------- the batch #

def test_three_spellings_of_one_key_are_refused_as_non_canonical_not_as_duplicates():
    """The audit's headline: on the tree before this change the batch was ACCEPTED, three
    thumbprints for one key. Strict means the first non-canonical proof is refused before
    the duplicate rule ever runs, and the nonce is not spent."""
    key = _P256()
    canonical = key.public_jwk()
    padded = dict(canonical, x=_padded(canonical["x"]))
    dirty = dict(canonical, y=_dirty_bits(canonical["y"]))
    assert len({jwk_thumbprint(j) for j in (canonical, padded, dirty)}) == 3

    calls = []
    with pytest.raises(ClaimsInvalid, match=_NOT_CANONICAL_X):
        _verify(_request(_proof(key, jwk=canonical), _proof(key, jwk=padded),
                         _proof(key, jwk=dirty)),
                batch_size=3, check_nonce=lambda n: calls.append(n) or True)
    assert calls == []


def test_a_canonical_batch_of_three_distinct_keys_is_accepted():
    keys = [_P256(), _P384(), _ED()]
    verified = _verify(_request(*(_proof(k) for k in keys)), batch_size=3)
    assert [v.public_jwk for v in verified] == [k.public_jwk() for k in keys]
    assert len({v.thumbprint for v in verified}) == 3
    assert [v.thumbprint for v in verified] == [jwk_thumbprint(k.public_jwk()) for k in keys]


def test_two_canonical_proofs_on_one_key_are_still_duplicates():
    key = _P256()
    with pytest.raises(ClaimsInvalid, match="bound to the same key"):
        _verify(_request(_proof(key), _proof(key)), batch_size=2)


def test_a_resolved_spelling_and_a_header_jwk_of_one_key_are_one_key():
    """Dedup is on the canonical form: a padded key from the resolver and the canonical
    one from a header jwk are the same key. (Before: two thumbprints, two credentials.)"""
    key = _P256()
    padded = dict(key.public_jwk(), x=_padded(key.public_jwk()["x"]))
    with pytest.raises(ClaimsInvalid, match="bound to the same key"):
        _verify(_request(_proof(key), _proof(key, key_param="kid")), batch_size=2,
                resolve_proof_key=lambda kid: padded)


# ------------------------------------------------ public_jwk is the minimal form #

_JUNK = {"kid": "attacker-kid", "alg": "ES384", "use": "enc", "key_ops": ["sign"], "ext": True,
         "x5u": "http://169.254.169.254/", "jku": "http://10.0.0.1/jwks", "blob": "Z" * 4000}


@pytest.mark.parametrize("factory", [_P256, _P384, _ED])
def test_public_jwk_has_exactly_the_rfc_7638_members(factory):
    """Extras are dropped, not refused: real wallets attach `use` and `kid` to their keys.
    What they must not do is reach the credential."""
    key = factory()
    verified, = _verify(_request(_proof(key, jwk=dict(key.public_jwk(), **_JUNK))))
    assert verified.public_jwk == key.public_jwk()
    assert set(verified.public_jwk) == ({"kty", "crv", "x", "y"} if key.public_jwk().get("y")
                                        else {"kty", "crv", "x"})
    assert verified.thumbprint == jwk_thumbprint(key.public_jwk())
    # The header is the wallet's, verbatim — for whoever wants to look, never for binding.
    assert verified.header["jwk"]["x5u"] == "http://169.254.169.254/"
    assert verified.header["jwk"]["blob"] == "Z" * 4000


def test_nothing_from_the_header_jwk_reaches_cnf_jwk():
    """The documented path: issue(holder_jwk=proof.public_jwk). Before, `x5u` and friends
    were signed into the issued credential."""
    from openvc.proof.sd_jwt import SdJwtVcProofSuite

    wallet, issuer = _P256(), _ED()
    proof, = _verify(_request(_proof(wallet, jwk=dict(wallet.public_jwk(), **_JUNK))))
    sd_jwt = SdJwtVcProofSuite().issue(
        {"iss": ISSUER, "given_name": "Ada"}, signing_key=issuer,
        holder_jwk=proof.public_jwk, vct="https://credentials.example/id")
    body = sd_jwt.split("~")[0].split(".")[1]
    cnf = json.loads(_raw(body))["cnf"]["jwk"]
    assert cnf == wallet.public_jwk()
    assert set(cnf) == {"kty", "crv", "x", "y"}


def test_public_jwk_is_a_fresh_dict_not_the_header_object():
    key = _P256()
    verified, = _verify(_request(_proof(key)))
    assert verified.public_jwk is not verified.header["jwk"]
    assert verified.public_jwk == verified.header["jwk"]


# ----------------------------------- a resolver's key is normalised, not refused #

@pytest.mark.parametrize("spell", [_padded, _non_alphabet, _dirty_bits])
def test_a_resolver_may_return_a_non_canonical_spelling_and_gets_it_normalised(spell):
    """The resolver is the caller's code, often reading a wallet-provider attestation —
    not the strict side. But what comes back, and the thumbprint, are canonical."""
    key = _P256()
    canonical = key.public_jwk()
    spelled = dict(canonical, x=spell(canonical["x"]), **_JUNK)
    verified, = _verify(_request(_proof(key, key_param="kid")),
                        resolve_proof_key=lambda kid: spelled)
    assert verified.key_source == "kid"
    assert verified.public_jwk == canonical
    assert verified.thumbprint == jwk_thumbprint(canonical)
    assert verified.thumbprint != jwk_thumbprint(spelled)


def test_a_resolver_returning_a_wrong_width_coordinate_is_refused_typed():
    key = _P256()
    wide = dict(key.public_jwk(), x=_wide(key.public_jwk()["x"]))
    with pytest.raises(ClaimsInvalid, match="cannot be thumbprinted: .*RFC 7518 §6.2.1.2"):
        _verify(_request(_proof(key, key_param="kid")), resolve_proof_key=lambda kid: wide)


def test_a_resolver_returning_an_off_curve_point_is_refused_typed_before_crypto():
    key = _P256()
    calls = []
    with pytest.raises(ClaimsInvalid, match="cannot be thumbprinted"):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: _off_curve(key.public_jwk()),
                check_nonce=lambda n: calls.append(n) or True)
    assert calls == []


def test_a_resolver_returning_another_valid_key_still_fails_the_signature():
    key, other = _P256(), _P256()
    with pytest.raises(SignatureInvalid):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: other.public_jwk())


# ---------------------------------------------- App. D: both sides canonical #

@pytest.mark.parametrize("spell", [_padded, _non_alphabet, _dirty_bits])
def test_an_attestation_that_spells_the_honest_key_non_canonically_still_matches(spell):
    """The attestation is not the strict side: a wallet provider's padded spelling of the
    very key that signed the proof must not read as "a key the wallet never claimed"."""
    key = _P256()
    canonical = key.public_jwk()
    spelled = dict(canonical, x=spell(canonical["x"]), kid="k", use="sig")
    assert jwk_thumbprint(spelled) != jwk_thumbprint(canonical)

    attested = _attestation(spelled)
    verified, = _verify(_request(_proof(key, header_extra={"key_attestation": attested})))
    assert verified.public_jwk == canonical
    assert verified.thumbprint == jwk_thumbprint(canonical)


def test_the_eudi_form_resolves_a_non_canonical_attested_key_and_returns_it_canonical():
    """`kid` is an index into `attested_keys` (the form the EUDI stacks send): the attested
    key is both the resolver's answer and the App. D comparison. Padded on the wire,
    canonical in the result."""
    key = _P256()
    canonical = key.public_jwk()
    padded = dict(canonical, x=_padded(canonical["x"]), use="sig", kid="0")
    header = {"kid": "0", "key_attestation": _attestation(padded)}
    verified, = _verify(
        _request(_proof(key, key_param=None, header_extra=header)),
        resolve_proof_key_in_context=lambda ctx: ctx.key_attestation.attested_keys[int(ctx.kid)])
    assert verified.key_source == "kid"
    assert verified.public_jwk == canonical
    assert verified.thumbprint == jwk_thumbprint(canonical)


def test_a_wrong_width_attested_key_is_still_refused_and_names_the_rule():
    """RFC 7518 §6.2.1.2 makes the full width a MUST: a 33-byte coordinate is not a
    spelling of the key, and the refusal says so (the message the existing suite pins)."""
    key = _P256()
    wide = dict(key.public_jwk(), x=_wide(key.public_jwk()["x"]))
    attested = _attestation(wide)
    with pytest.raises(ClaimsInvalid, match="an attested key cannot be thumbprinted: .*RFC 7518"):
        _verify(_request(_proof(key, header_extra={"key_attestation": attested})))


def test_a_stranger_in_attested_keys_is_still_not_among_them():
    key, stranger = _P256(), _P256()
    attested = _attestation(stranger.public_jwk())
    with pytest.raises(ClaimsInvalid, match="not among the key attestation's attested_keys"):
        _verify(_request(_proof(key, header_extra={"key_attestation": attested})))


@pytest.mark.parametrize("attested_keys", [
    [{}], [{"kty": "EC"}], [{"kty": "XX", "x": "a"}],
    [{"kty": "EC", "crv": "P-256", "x": 123, "y": "a"}],
    [{"kty": "EC", "crv": "secp256k1", "x": "a", "y": "b"}],
    # unhashable kty / crv: a set lookup on them would be a bare TypeError
    [{"kty": "EC", "crv": ["P-256"], "x": "a", "y": "b"}],
    [{"kty": "EC", "crv": {"a": 1}, "x": "a", "y": "b"}],
    [{"kty": ["EC"], "crv": "P-256", "x": "a", "y": "b"}],
    [{"kty": None, "crv": None, "x": "a"}],
], ids=["empty", "kty-only", "unknown-kty", "non-string-x", "secp256k1",
        "list-crv", "object-crv", "list-kty", "null-kty-crv"])
def test_a_malformed_attested_key_is_typed_not_leaked(attested_keys):
    key = _P256()
    attested = _attestation(attested_keys=attested_keys)
    with pytest.raises(ClaimsInvalid) as info:
        _verify(_request(_proof(key, header_extra={"key_attestation": attested})))
    assert type(info.value) is ClaimsInvalid


def _x25519_jwk():
    pub = x25519.X25519PrivateKey.generate().public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "X25519", "use": "enc", "x": _b64u(raw)}


def _p521_jwk():
    nums = ec.generate_private_key(ec.SECP521R1()).public_key().public_numbers()
    return {"kty": "EC", "crv": "P-521", "x": _b64u(nums.x.to_bytes(66, "big")),
            "y": _b64u(nums.y.to_bytes(66, "big"))}


def _rsa_jwk():
    nums = rsa.generate_private_key(65537, 2048).public_key().public_numbers()
    return {"kty": "RSA", "n": _b64u(nums.n.to_bytes(256, "big")), "e": _b64u(b"\x01\x00\x01")}


@pytest.mark.parametrize("sibling", [_x25519_jwk, _p521_jwk, _rsa_jwk],
                         ids=["X25519", "P-521", "RSA"])
def test_a_sibling_key_of_another_type_listed_before_the_honest_key_is_passed_over(sibling):
    """A multi-key attestation (an encryption key next to the signing key) is a real wallet
    shape. The sibling cannot be the proof key — it could never bind to the proof's alg —
    so it is read as RFC 7638 reads it and skipped, as before; only the match matters."""
    key = _P256()
    attested = _attestation(sibling(), key.public_jwk())
    verified, = _verify(_request(_proof(key, header_extra={"key_attestation": attested})))
    assert verified.public_jwk == key.public_jwk()


def test_a_sibling_of_another_type_spelled_non_canonically_is_passed_over_too():
    """Nothing about a sibling is canonicalised or judged, including its spelling."""
    key = _P256()
    sibling = _x25519_jwk()
    sibling["x"] = _padded(sibling["x"])
    attested = _attestation(sibling, key.public_jwk())
    verified, = _verify(_request(_proof(key, header_extra={"key_attestation": attested})))
    assert verified.thumbprint == jwk_thumbprint(key.public_jwk())


@pytest.mark.parametrize("junk_first", [True, False], ids=["junk-before", "junk-after"])
@pytest.mark.parametrize("junk, expect", [
    ({"kty": "XX", "x": "a"}, "an attested key cannot be thumbprinted"),
    ({"kty": "EC", "crv": "P-256", "x": "a"}, "an attested key cannot be thumbprinted"),
    ({"kty": "EC", "crv": "P-256", "x": 123, "y": "a"}, "an attested key cannot be thumbprinted"),
], ids=["unknown-kty", "missing-y", "non-string-x"])
def test_junk_in_attested_keys_refuses_wherever_it_sits(junk, expect, junk_first):
    """A key RFC 7638 cannot digest refuses the proof, whatever else the attestation lists
    and in whatever order: every entry is read before any is matched (before this change,
    and on the tree before it, junk listed after the matching key went unread)."""
    key = _P256()
    keys = (junk, key.public_jwk()) if junk_first else (key.public_jwk(), junk)
    attested = _attestation(*keys)
    with pytest.raises(ClaimsInvalid, match=expect):
        _verify(_request(_proof(key, header_extra={"key_attestation": attested})))


@pytest.mark.parametrize("junk_first", [True, False], ids=["junk-before", "junk-after"])
def test_a_malformed_key_of_a_bindable_shape_refuses_wherever_it_sits(junk_first):
    """Deliberately stricter than before on the attestation side: a P-256 sibling of the wrong
    width or off the curve is not a key, a bindable shape is validated as one, and the list
    order does not matter."""
    key = _P256()
    other = _P256().public_jwk()
    for junk, expect in ((dict(other, x=_wide(other["x"])), "RFC 7518 §6.2.1.2"),
                         (_off_curve(other), "is not a valid P-256 public key")):
        keys = (junk, key.public_jwk()) if junk_first else (key.public_jwk(), junk)
        attested = _attestation(*keys)
        message = f"an attested key cannot be thumbprinted: .*{expect}"
        with pytest.raises(ClaimsInvalid, match=message):
            _verify(_request(_proof(key, header_extra={"key_attestation": attested})))


# ------------------------------------------------- openvc.keys.canonical_public_jwk #

@pytest.mark.parametrize("factory", [_P256, _P384, _ED])
def test_canonical_public_jwk_is_the_identity_on_a_backend_key(factory):
    from openvc.keys import canonical_public_jwk

    jwk = factory().public_jwk()
    assert canonical_public_jwk(jwk) == jwk
    assert canonical_public_jwk(jwk, strict=True) == jwk
    assert list(canonical_public_jwk(jwk)) == list(jwk)          # public_jwk() member order


def test_canonical_public_jwk_drops_every_other_member_and_returns_a_fresh_dict():
    from openvc.keys import canonical_public_jwk

    jwk = _P256().public_jwk()
    noisy = dict(jwk, **_JUNK)
    out = canonical_public_jwk(noisy, strict=True)
    assert out == jwk and set(out) == {"kty", "crv", "x", "y"}
    out["x"] = "tampered"
    assert noisy["x"] == jwk["x"]


@pytest.mark.parametrize("spell", [_padded, _non_alphabet, _dirty_bits])
def test_canonical_public_jwk_normalises_a_spelling_and_strict_refuses_it(spell):
    from openvc.keys import InvalidKey, NonCanonicalKey, canonical_public_jwk

    jwk = _P256().public_jwk()
    spelled = dict(jwk, y=spell(jwk["y"]))
    assert _raw(spelled["y"]) == _raw(jwk["y"])
    assert canonical_public_jwk(spelled) == jwk
    with pytest.raises(NonCanonicalKey, match=r"\['y'\] are not canonical base64url") as info:
        canonical_public_jwk(spelled, strict=True)
    assert spelled["y"] not in str(info.value)
    assert isinstance(info.value, InvalidKey)        # a caller catching InvalidKey still does


def test_a_key_that_is_not_a_key_is_never_reported_as_merely_non_canonical():
    """The typed split: junk is `InvalidKey`, a spelling is `NonCanonicalKey` — in both modes."""
    from openvc.keys import InvalidKey, NonCanonicalKey, canonical_public_jwk

    jwk = _P256().public_jwk()
    for junk in (dict(jwk, x=_wide(jwk["x"])), _off_curve(jwk), dict(jwk, x=123)):
        for strict in (False, True):
            with pytest.raises(InvalidKey) as info:
                canonical_public_jwk(junk, strict=strict)
            assert not isinstance(info.value, NonCanonicalKey)


def test_canonical_public_jwk_refuses_a_wrong_width_even_when_lenient():
    from openvc.keys import InvalidKey, canonical_public_jwk

    jwk = _P256().public_jwk()
    for member in ("x", "y"):
        expect = (rf"'{member}' must decode to the 32-byte fixed width of P-256 "
                  r"\(RFC 7518 §6.2.1.2\), got 33 bytes")
        with pytest.raises(InvalidKey, match=expect):
            canonical_public_jwk(dict(jwk, **{member: _wide(jwk[member])}))
    short = _b64u(_raw(jwk["x"])[1:])
    with pytest.raises(InvalidKey, match="got 31 bytes"):
        canonical_public_jwk(dict(jwk, x=short))
    p384 = _P384().public_jwk()
    with pytest.raises(InvalidKey, match="48-byte fixed width of P-384"):
        canonical_public_jwk(dict(p384, x=_b64u(_raw(p384["x"])[1:])))


def test_canonical_public_jwk_refuses_an_off_curve_point():
    from openvc.keys import InvalidKey, canonical_public_jwk

    with pytest.raises(InvalidKey, match="is not a valid P-256 public key"):
        canonical_public_jwk(_off_curve(_P256().public_jwk()))


@pytest.mark.parametrize("jwk, expect", [
    ({"kty": "EC", "crv": "P-256", "x": 123, "y": "a"}, "needs a string 'x' member"),
    ({"kty": "EC", "crv": "P-256", "y": "a"}, "needs a string 'x' member"),
    ({"kty": "OKP", "crv": "Ed25519"}, "needs a string 'x' member"),
    ({"kty": "EC", "crv": "P-256", "x": "ü" * 43, "y": "a"}, "'x' is not base64url"),
    ({"kty": "EC", "crv": "P-256", "x": "A" * 43 + "\ud800", "y": "a"},
     r"'x' holds a lone UTF-16 surrogate \(U\+D800 at index 43\)"),
    ({"kty": "OKP", "crv": "Ed25519", "x": "\udfff" + "A" * 43},
     r"'x' holds a lone UTF-16 surrogate \(U\+DFFF at index 0\)"),
    ({"kty": "EC", "crv": "secp256k1", "x": "a", "y": "b"}, "no canonical public form"),
    ({"kty": "OKP", "crv": "X25519", "x": "a"}, "no canonical public form"),
    ({"kty": "EC", "x": "a", "y": "b"}, "no canonical public form"),
    ({"kty": "EC", "crv": ["P-256"], "x": "a", "y": "b"}, "crv=list"),
    ({"kty": "EC", "crv": "C" * 33, "x": "a", "y": "b"}, "crv=str: EC P-256"),
    ({"kty": "RSA", "n": "AQAB", "e": "AQAB"}, "no canonical public form"),
    ({"kty": "oct", "k": "AQAB"}, "no canonical public form"),
    ({"kty": "AKP", "alg": "ML-DSA-65", "pub": "AA"}, "unsupported JWK kty 'AKP'"),
    ({"kty": 5}, "no string 'kty'"),
    ({}, "no string 'kty'"),
])
def test_canonical_public_jwk_fails_closed_with_a_typed_error(jwk, expect):
    from openvc.keys import InvalidKey, canonical_public_jwk

    with pytest.raises(InvalidKey, match=expect) as info:
        canonical_public_jwk(jwk)
    assert "\ud800" not in str(info.value) and "\udfff" not in str(info.value)


def test_a_lone_surrogate_in_the_header_jwk_is_typed_and_named_by_code_point():
    key = _P256()
    spelled = dict(key.public_jwk(), x=key.public_jwk()["x"] + "\ud800")
    expect = r"key proof jwk cannot be thumbprinted: .*U\+D800 at index 43"
    with pytest.raises(ClaimsInvalid, match=expect) as info:
        _verify(_request(_proof(key, jwk=spelled)))
    assert "\ud800" not in str(info.value)


@pytest.mark.parametrize("not_a_jwk", [[1], "abc", None, 5, b"x", ({"kty": "EC"},)],
                         ids=["list", "str", "None", "int", "bytes", "tuple"])
def test_canonical_public_jwk_refuses_a_non_object_typed(not_a_jwk):
    from openvc.keys import InvalidKey, canonical_public_jwk

    with pytest.raises(InvalidKey, match="JWK must be a JSON object"):
        canonical_public_jwk(not_a_jwk)


@pytest.mark.parametrize("jwk", [
    {"kty": "A" * 100_000},
    {"kty": "EC", "crv": "C" * 100_000, "x": "a", "y": "b"},
    {"kty": "K" * 100_000, "crv": "P-256", "x": "a", "y": "b"},
    {"kty": "EC", "crv": "P-256", "x": "A" * 100_000, "y": "b"},
    {"kty": "EC", "crv": "P-256", "x": "!" * 100_000, "y": "b"},
], ids=["kty", "crv", "kty-with-crv", "x", "x-non-b64"])
def test_canonical_public_jwk_messages_are_bounded(jwk):
    from openvc.keys import InvalidKey, canonical_public_jwk

    with pytest.raises(InvalidKey) as info:
        canonical_public_jwk(jwk, strict=True)
    assert len(str(info.value)) < 200


# ---------------------------------------- Ed25519 point encodings (RFC 8032 §5.1.3) #

_P_ED = 2**255 - 19
_D_ED = (-121665 * pow(121666, -1, _P_ED)) % _P_ED
_SQRT_M1 = pow(2, (_P_ED - 1) // 4, _P_ED)
_B_ENC = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")


def _sqrt_ed(a):
    a %= _P_ED
    c = pow(a, (_P_ED + 3) // 8, _P_ED)
    if (c * c) % _P_ED == a:
        return c
    c = (c * _SQRT_M1) % _P_ED
    return c if (c * c) % _P_ED == a else None


def _ed_add(P, Q):
    (x1, y1), (x2, y2) = P, Q
    k = _D_ED * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * pow(1 + k, -1, _P_ED) % _P_ED,
            (y1 * y2 + x1 * x2) * pow(1 - k, -1, _P_ED) % _P_ED)


def _small_order_ys():
    """Derived from the curve, not copied: 1 (identity), p-1 (order 2), 0 (order 4) and the
    two y with y² = (-1 ± sqrt(1+d))/d, whose double lies on y = 0 (order 8)."""
    ys = {0, 1, _P_ED - 1}
    root = _sqrt_ed(1 + _D_ED)
    for r in (root, _P_ED - root):
        y = _sqrt_ed((-1 + r) * pow(_D_ED, -1, _P_ED))
        if y is not None:
            ys |= {y, _P_ED - y}
    return ys


def _ed_enc(y, sign=0):
    enc = bytearray(y.to_bytes(32, "little"))
    enc[31] |= sign
    return bytes(enc)


def _ed_jwk(enc):
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(enc)}


def test_the_small_order_set_is_the_torsion_subgroup():
    """Self-check of the test's own derivation: five y values, and each point of order 8
    doubles onto y = 0, then onto the point of order 2, then onto the identity."""
    ys = _small_order_ys()
    assert len(ys) == 5
    for y in ys - {0, 1, _P_ED - 1}:
        x = _sqrt_ed((y * y - 1) * pow(_D_ED * y * y + 1, -1, _P_ED))
        assert x is not None
        p2 = _ed_add((x, y), (x, y))
        p4 = _ed_add(p2, p2)
        assert p2[1] == 0 and p4 == (0, _P_ED - 1) and _ed_add(p4, p4) == (0, 1)
    # libsodium's `ge25519_has_small_order` table, little-endian
    assert int.from_bytes(bytes.fromhex(
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little") in ys
    assert int.from_bytes(bytes.fromhex(
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little") in ys


@pytest.mark.parametrize("label, enc", [
    ("identity y=1", _ed_enc(1)),
    ("identity y=1 sign-bit", _ed_enc(1, 0x80)),
    ("identity y=1+p", _ed_enc(1 + _P_ED)),
    ("identity y=1+p sign-bit", _ed_enc(1 + _P_ED, 0x80)),
    ("y=p (non-canonical 0)", _ed_enc(_P_ED)),
    ("y=p+18", _ed_enc(_P_ED + 18)),
    ("all 0xff", b"\xff" * 32),
    ("all 0x00", b"\x00" * 32),
])
def test_a_non_canonical_or_identity_ed25519_encoding_is_refused_in_both_modes(label, enc):
    from openvc.keys import InvalidKey, NonCanonicalKey, canonical_public_jwk

    for strict in (False, True):
        with pytest.raises(InvalidKey, match="Ed25519 point") as info:
            canonical_public_jwk(_ed_jwk(enc), strict=strict)
        assert not isinstance(info.value, NonCanonicalKey)    # it is not a key, not a spelling
        assert _b64u(enc) not in str(info.value)


@pytest.mark.parametrize("sign", [0, 0x80], ids=["sign-0", "sign-1"])
@pytest.mark.parametrize("y", sorted(_small_order_ys()),
                         ids=["y=0", "y=1", "y=order8-a", "y=order8-b", "y=p-1"])
def test_every_small_order_ed25519_point_is_refused(y, sign):
    """All eight torsion points, both sign bits of each y (ten encodings; two name the same
    point as another, which is exactly the duplicate-spelling problem)."""
    from openvc.keys import InvalidKey, canonical_public_jwk

    with pytest.raises(InvalidKey, match="small-order Ed25519 point"):
        canonical_public_jwk(_ed_jwk(_ed_enc(y, sign)))


def test_a_real_ed25519_key_is_accepted_and_its_negation_is_another_real_key():
    from openvc.keys import canonical_public_jwk

    jwk = _ED().public_jwk()
    assert canonical_public_jwk(jwk, strict=True) == jwk
    assert jwk_thumbprint(canonical_public_jwk(jwk)) == jwk_thumbprint(jwk)
    raw = bytearray(_raw(jwk["x"]))
    raw[31] ^= 0x80                                          # -A: a different, valid point
    negated = _ed_jwk(bytes(raw))
    assert canonical_public_jwk(negated, strict=True) == negated


def test_forged_proofs_under_the_identity_point_are_refused_before_the_nonce():
    """The review's headline: [S]B == R + [k]A holds for A = identity with R = B, S = 1, so a
    proof under it needs no private key. Four strict-canonical spellings → four thumbprints
    → a 4-proof batch minted four credentials on the tree before this change."""
    forged = _B_ENC + (1).to_bytes(32, "little")
    spellings = [_ed_enc(1), _ed_enc(1, 0x80), _ed_enc(1 + _P_ED), _ed_enc(1 + _P_ED, 0x80)]
    assert len({jwk_thumbprint(_ed_jwk(e)) for e in spellings}) == 4

    def forged_proof(enc):
        header = {"typ": "openid4vci-proof+jwt", "alg": "EdDSA", "jwk": _ed_jwk(enc)}
        claims = {"aud": ISSUER, "iat": NOW_TS, "nonce": NONCE}
        return ".".join((_b64u(json.dumps(header).encode()), _b64u(json.dumps(claims).encode()),
                         _b64u(forged)))

    calls = []
    expect = "key proof jwk cannot be thumbprinted: .*Ed25519 point"
    with pytest.raises(ClaimsInvalid, match=expect):
        _verify(_request(forged_proof(spellings[0])),
                check_nonce=lambda n: calls.append(n) or True)
    with pytest.raises(ClaimsInvalid, match="Ed25519 point"):
        _verify(_request(*(forged_proof(e) for e in spellings)), batch_size=4,
                check_nonce=lambda n: calls.append(n) or True)
    assert calls == []


def test_a_resolver_returning_the_identity_point_is_refused_typed():
    key = _ED()
    with pytest.raises(ClaimsInvalid, match="cannot be thumbprinted: .*small-order Ed25519 point"):
        _verify(_request(_proof(key, key_param="kid")),
                resolve_proof_key=lambda kid: _ed_jwk(_ed_enc(1)))


def test_a_p256_coordinate_at_or_above_p_is_refused_by_the_backend():
    """Pins what `from_encoded_point` does for EC (the review checked it): a point with a tiny
    x can be spelled with x + p in 32 bytes; `EllipticCurvePublicNumbers` would reduce it
    silently, `from_encoded_point` refuses it, and so does the helper."""
    from openvc.keys import InvalidKey, canonical_public_jwk

    p256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    x = 0
    while True:
        rhs = (x ** 3 - 3 * x + b) % p256
        if pow(rhs, (p256 - 1) // 2, p256) == 1:
            y = pow(rhs, (p256 + 1) // 4, p256)
            break
        x += 1
    assert (y * y) % p256 == rhs and x + p256 < 2**256
    jwk = {"kty": "EC", "crv": "P-256", "x": _b64u(x.to_bytes(32, "big")),
           "y": _b64u(y.to_bytes(32, "big"))}
    assert canonical_public_jwk(jwk, strict=True) == jwk
    with pytest.raises(InvalidKey, match="is not a valid P-256 public key"):
        canonical_public_jwk(dict(jwk, x=_b64u((x + p256).to_bytes(32, "big"))))


def test_canonical_public_jwk_is_public_api():
    import openvc.keys as keys

    assert "canonical_public_jwk" in keys.__all__ and "NonCanonicalKey" in keys.__all__
    assert callable(keys.canonical_public_jwk)
