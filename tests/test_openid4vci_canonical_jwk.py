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
  * `openvc.keys.canonical_public_jwk`, the helper behind all of it.

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
])
def test_a_malformed_attested_key_is_typed_not_leaked(attested_keys):
    key = _P256()
    attested = _attestation(attested_keys=attested_keys)
    with pytest.raises(ClaimsInvalid):
        _verify(_request(_proof(key, header_extra={"key_attestation": attested})))


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


@pytest.mark.parametrize("junk, expect", [
    ({"kty": "XX", "x": "a"}, "an attested key cannot be thumbprinted"),
    ({"kty": "EC", "crv": "P-256", "x": "a"}, "an attested key cannot be thumbprinted"),
    ({"kty": "EC", "crv": "P-256", "x": 123, "y": "a"}, "an attested key cannot be thumbprinted"),
], ids=["unknown-kty", "missing-y", "non-string-x"])
def test_junk_in_attested_keys_still_refuses_even_next_to_the_honest_key(junk, expect):
    """Unchanged from before: a key RFC 7638 cannot digest refuses the proof, whatever else
    the attestation lists."""
    key = _P256()
    attested = _attestation(junk, key.public_jwk())
    with pytest.raises(ClaimsInvalid, match=expect):
        _verify(_request(_proof(key, header_extra={"key_attestation": attested})))


def test_a_malformed_key_of_a_bindable_shape_refuses_even_next_to_the_honest_key():
    """Deliberately stricter than before on the attestation side: a P-256 sibling of the wrong
    width or off the curve is not a key, and a bindable shape is validated as one."""
    key = _P256()
    other = _P256().public_jwk()
    for junk, expect in ((dict(other, x=_wide(other["x"])), "RFC 7518 §6.2.1.2"),
                         (_off_curve(other), "is not a valid P-256 public key")):
        attested = _attestation(junk, key.public_jwk())
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
    ({"kty": "EC", "crv": ["P-256"], "x": "a", "y": "b"}, "crv='list'"),
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


def test_canonical_public_jwk_is_public_api():
    import openvc.keys as keys

    assert "canonical_public_jwk" in keys.__all__ and "NonCanonicalKey" in keys.__all__
    assert callable(keys.canonical_public_jwk)
