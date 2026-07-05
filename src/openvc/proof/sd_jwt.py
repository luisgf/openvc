"""
openvc.proof.sd_jwt — SD-JWT VC proof suite (selective disclosure).

Implements the IETF SD-JWT VC family:
  * draft-ietf-oauth-selective-disclosure-jwt (the SD-JWT mechanism)
  * draft-ietf-oauth-sd-jwt-vc (the VC profile: ``vct``, ``cnf``, ``status`` ...)

The third proof profile alongside VC-JWT (:mod:`openvc.proof.vc_jwt`) and Data
Integrity — and the format EUDI/ARF converges on. It reuses the same JOSE
machinery: the ``SigningKey`` backend (HSM-friendly, the private key never enters
the process) and the fixed ``{ES256, EdDSA}`` algorithm allow-list checked before
any crypto runs.

How SD-JWT works, briefly
-------------------------
Selectively-disclosable claims are removed from the issuer-signed JWT and each is
replaced by the **digest** of a *disclosure* — a salted ``[salt, name, value]``
(object) or ``[salt, value]`` (array element) blob. The digests live under ``_sd``
(objects) or as ``{"...": digest}`` (array elements). The combined presentation is

    <issuer-signed-jwt>~<disclosure 1>~...~<disclosure N>~<optional KB-JWT>

The holder chooses which disclosures to send; the verifier hashes each received
disclosure, matches it against the digests, and reconstructs only the disclosed
claims. A **Key Binding JWT** (``typ: kb+jwt``), signed by the holder key named in
the issuer's ``cnf``, binds a presentation to an audience + nonce and to the exact
set of disclosures (via ``sd_hash``).

Revocation is out of band: an SD-JWT VC's ``status`` claim can carry an IETF Token
Status List reference — check it with :func:`openvc.status.check_token_status`
over the verified claims.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable

from ..keys import KeyBackendError, verify_signature
from .vc_jwt import (
    ALLOWED_ALGS,
    ClaimsInvalid,
    MalformedToken,
    ProofError,
    SignatureInvalid,
    SigningKey,
    UnsupportedAlgorithm,
)

DEFAULT_LEEWAY_S = 60
_HASHES = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
_DEFAULT_HASH = "sha-256"
_ISSUER_TYP = "dc+sd-jwt"                       # current draft (older: vc+sd-jwt)
_ACCEPTED_ISSUER_TYP = frozenset({"dc+sd-jwt", "vc+sd-jwt"})
_KB_TYP = "kb+jwt"
_SALT_BYTES = 16                               # 128-bit salt (spec minimum)


class SdJwtError(ProofError):
    """Malformed SD-JWT structure, disclosure, or key-binding."""


# --------------------------------------------------------------------------- #
# base64url + disclosure primitives
# --------------------------------------------------------------------------- #

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def make_object_disclosure(salt: str, name: str, value: Any) -> str:
    """Encode an object-property disclosure ``[salt, name, value]``."""
    return _b64url_encode(_json_bytes([salt, name, value]))


def make_array_disclosure(salt: str, value: Any) -> str:
    """Encode an array-element disclosure ``[salt, value]``."""
    return _b64url_encode(_json_bytes([salt, value]))


def disclosure_digest(disclosure: str, *, hash_name: str = _DEFAULT_HASH) -> str:
    """The base64url digest of a disclosure string — hashed exactly as received
    (never re-serialized), which is why the verifier needs no canonicalization."""
    try:
        hasher = _HASHES[hash_name]
    except KeyError as exc:
        raise SdJwtError(f"unsupported _sd_alg {hash_name!r}") from exc
    return _b64url_encode(hasher(disclosure.encode("ascii")).digest())


# --------------------------------------------------------------------------- #
# recursive unpacking (the security-critical core)
# --------------------------------------------------------------------------- #

def _sd_digests(sd: Any) -> list[str]:
    if sd is None:
        return []
    if not isinstance(sd, list) or not all(isinstance(d, str) for d in sd):
        raise SdJwtError("_sd must be an array of digest strings")
    return sd


def _unpack(node: Any, disclosures: dict[str, list], used: set[str], seen: set[str]) -> Any:
    """Rebuild *node*, replacing ``_sd`` digests and ``{"...": digest}`` array
    elements with the disclosed values. Rejects duplicate digests, digests reused
    by two disclosures, and disclosures that would overwrite an existing claim."""
    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, value in node.items():
            if key == "_sd":
                continue                       # processed below
            if key == "...":
                raise SdJwtError("'...' is only valid as an array element")
            result[key] = _unpack(value, disclosures, used, seen)
        for digest in _sd_digests(node.get("_sd")):
            if digest in seen:
                raise SdJwtError("duplicate digest in payload")
            seen.add(digest)
            disclosure = disclosures.get(digest)
            if disclosure is None:
                continue                       # decoy or simply not disclosed
            if len(disclosure) != 3:
                raise SdJwtError("object disclosure must be [salt, name, value]")
            name = disclosure[1]
            if not isinstance(name, str):
                raise SdJwtError("disclosure claim name must be a string")
            if name in ("_sd", "..."):
                raise SdJwtError(f"disclosure claim name {name!r} is reserved")
            if name in result:
                raise SdJwtError(f"disclosure would overwrite claim {name!r}")
            used.add(digest)
            result[name] = _unpack(disclosure[2], disclosures, used, seen)
        return result
    if isinstance(node, list):
        out: list[Any] = []
        for element in node:
            if isinstance(element, dict) and set(element) == {"..."}:
                digest = element["..."]
                if not isinstance(digest, str):
                    raise SdJwtError("array digest must be a string")
                if digest in seen:
                    raise SdJwtError("duplicate digest in payload")
                seen.add(digest)
                disclosure = disclosures.get(digest)
                if disclosure is None:
                    continue                   # undisclosed array element
                if len(disclosure) != 2:
                    raise SdJwtError("array disclosure must be [salt, value]")
                used.add(digest)
                out.append(_unpack(disclosure[1], disclosures, used, seen))
            else:
                out.append(_unpack(element, disclosures, used, seen))
        return out
    return node


# --------------------------------------------------------------------------- #
# result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedSdJwt:
    claims: dict[str, Any]         # the fully-disclosed claim set (``_sd`` resolved)
    issuer: str                    # ``iss``
    vct: str | None                # verifiable credential type
    key_bound: bool                # a valid KB-JWT was present and verified
    confirmation: dict[str, Any] | None   # the ``cnf`` claim, if any


# --------------------------------------------------------------------------- #
# proof suite
# --------------------------------------------------------------------------- #

class SdJwtVcProofSuite:
    """SD-JWT VC issuance, holder presentation, and verification."""

    def __init__(
        self, *, leeway_s: int = DEFAULT_LEEWAY_S, hash_name: str = _DEFAULT_HASH
    ) -> None:
        if hash_name not in _HASHES:
            raise SdJwtError(f"unsupported hash {hash_name!r}")
        self._leeway = leeway_s
        self._hash_name = hash_name

    # -- untrusted inspection --------------------------------------------- #

    def peek_issuer(self, sd_jwt: str) -> tuple[str, str | None]:
        """Return (iss, kid) from the issuer-signed JWT WITHOUT verifying.
        UNTRUSTED — use only to select which key to resolve."""
        header, payload, _, _ = self._decode_jws(sd_jwt.split("~", 1)[0])
        iss = payload.get("iss")
        if not iss or not isinstance(iss, str):
            raise MalformedToken("no iss in the issuer-signed JWT")
        return iss, header.get("kid")

    # -- issuance --------------------------------------------------------- #

    def issue(
        self,
        claims: dict[str, Any],
        *,
        signing_key: SigningKey,
        disclosable: Iterable[str] = (),
        holder_jwk: dict[str, Any] | None = None,
        vct: str | None = None,
        expires_in_s: int | None = None,
        decoys: int = 0,
    ) -> str:
        """Issue an SD-JWT VC: ``<issuer-jwt>~<disclosure>~...~``.

        ``disclosable`` names the top-level claims to make selectively
        disclosable (each leaves the JWT for a disclosure + an ``_sd`` digest).
        ``holder_jwk`` binds the credential to a holder key (``cnf``) for later
        key binding. ``decoys`` adds that many decoy digests (privacy). The raw
        signature is produced by ``signing_key`` — HSM/Vault friendly.
        """
        if signing_key.alg not in ALLOWED_ALGS:
            raise UnsupportedAlgorithm(f"key alg {signing_key.alg!r} not permitted")

        now = int(time.time())
        payload: dict[str, Any] = dict(claims)
        payload.setdefault("iat", now)
        if vct is not None:
            payload["vct"] = vct
        if not payload.get("iss"):
            raise SdJwtError("an SD-JWT VC needs an 'iss' claim")
        if not payload.get("vct"):
            raise SdJwtError("an SD-JWT VC needs a 'vct' claim")
        if expires_in_s is not None:
            payload["exp"] = now + expires_in_s
        if holder_jwk is not None:
            payload["cnf"] = {"jwk": holder_jwk}

        disclosures: list[str] = []
        digests: list[str] = []
        for name in disclosable:
            if name not in payload:
                raise SdJwtError(f"disclosable claim {name!r} is not in the claims")
            disclosure = make_object_disclosure(
                _b64url_encode(secrets.token_bytes(_SALT_BYTES)), name, payload.pop(name))
            disclosures.append(disclosure)
            digests.append(disclosure_digest(disclosure, hash_name=self._hash_name))
        digest_size = _HASHES[self._hash_name]().digest_size
        for _ in range(decoys):
            digests.append(_b64url_encode(secrets.token_bytes(digest_size)))
        if digests:
            payload["_sd"] = sorted(digests)           # sorted: order leaks nothing
            payload["_sd_alg"] = self._hash_name

        header = {"typ": _ISSUER_TYP, "alg": signing_key.alg, "kid": signing_key.kid}
        issuer_jwt = self._sign_compact(header, payload, signing_key)
        return issuer_jwt + "~" + "".join(d + "~" for d in disclosures)

    # -- holder presentation ---------------------------------------------- #

    def create_presentation(
        self,
        sd_jwt: str,
        *,
        holder_key: SigningKey,
        audience: str,
        nonce: str,
    ) -> str:
        """Holder side: attach a Key Binding JWT over the (all-disclosure)
        presentation, bound to *audience* and *nonce*. Returns the full
        ``<issuer-jwt>~<disclosures>~<KB-JWT>``."""
        if holder_key.alg not in ALLOWED_ALGS:
            raise UnsupportedAlgorithm(f"holder key alg {holder_key.alg!r} not permitted")
        issuer_jwt, disclosures, _ = self._split(sd_jwt)
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        sd_hash = _b64url_encode(
            _HASHES[self._hash_name](presented.encode("ascii")).digest())
        header = {"typ": _KB_TYP, "alg": holder_key.alg}
        payload = {"iat": int(time.time()), "aud": audience, "nonce": nonce, "sd_hash": sd_hash}
        return presented + self._sign_compact(header, payload, holder_key)

    # -- verification ------------------------------------------------------ #

    def verify(
        self,
        presentation: str,
        *,
        public_key_jwk: dict[str, Any],
        audience: str | None = None,
        nonce: str | None = None,
        require_key_binding: bool = False,
        expected_vct: str | None = None,
    ) -> VerifiedSdJwt:
        """Verify an SD-JWT (VC) presentation end to end.

        Verifies the issuer signature + temporal claims, validates and unpacks the
        disclosures, and — if a KB-JWT is present (or required) — verifies it
        against the holder key in ``cnf`` and checks ``aud`` / ``nonce`` /
        ``sd_hash``.
        """
        issuer_jwt, disclosures, kb_jwt = self._split(presentation)
        header, claims, signing_input, signature = self._decode_jws(issuer_jwt)

        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:                     # allow-list BEFORE crypto
            raise UnsupportedAlgorithm(f"algorithm {alg!r} is not permitted")
        if header.get("typ") not in _ACCEPTED_ISSUER_TYP:
            raise SdJwtError(f"unexpected issuer JWT typ {header.get('typ')!r}")
        self._verify_signature(alg, public_key_jwk, signing_input, signature,
                               what="issuer JWT")
        self._check_temporal(claims)

        iss = claims.get("iss")
        if not isinstance(iss, str):
            raise ClaimsInvalid("iss claim is missing or not a string")

        hash_name = claims.get("_sd_alg", _DEFAULT_HASH)
        if hash_name not in _HASHES:
            raise SdJwtError(f"unsupported _sd_alg {hash_name!r}")
        by_digest = self._index_disclosures(disclosures, hash_name)
        used: set[str] = set()
        unpacked = _unpack(claims, by_digest, used, set())
        unreferenced = set(by_digest) - used
        if unreferenced:
            raise SdJwtError(
                f"{len(unreferenced)} disclosure(s) not referenced by any digest")
        unpacked.pop("_sd_alg", None)

        vct = unpacked.get("vct")
        if expected_vct is not None and vct != expected_vct:
            raise ClaimsInvalid(f"vct {vct!r} != expected {expected_vct!r}")

        key_bound = self._verify_key_binding(
            kb_jwt, issuer_jwt, disclosures, claims.get("cnf"),
            hash_name=hash_name, audience=audience, nonce=nonce,
            required=require_key_binding)

        return VerifiedSdJwt(
            claims=unpacked, issuer=iss, vct=vct if isinstance(vct, str) else None,
            key_bound=key_bound, confirmation=claims.get("cnf"))

    # -- internals --------------------------------------------------------- #

    @staticmethod
    def _split(sd_jwt: str) -> tuple[str, list[str], str]:
        """(issuer-jwt, [disclosures], kb-jwt) — kb is '' when absent."""
        parts = sd_jwt.split("~")
        if len(parts) < 2:
            raise MalformedToken("not an SD-JWT (no '~' separator)")
        return parts[0], [p for p in parts[1:-1] if p], parts[-1]

    @staticmethod
    def _decode_jws(jws: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
        """(header, payload, signing_input, signature) for a compact JWS."""
        try:
            header_b64, payload_b64, sig_b64 = jws.split(".")
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
            signature = _b64url_decode(sig_b64)
        except (ValueError, json.JSONDecodeError) as exc:
            raise MalformedToken("not a valid compact JWS") from exc
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return header, payload, signing_input, signature

    @staticmethod
    def _sign_compact(header: dict[str, Any], payload: dict[str, Any], key: SigningKey) -> str:
        signing_input = (
            f"{_b64url_encode(_json_bytes(header))}.{_b64url_encode(_json_bytes(payload))}")
        signature = key.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url_encode(signature)}"

    @staticmethod
    def _verify_signature(
        alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes, *, what: str
    ) -> None:
        try:
            ok = verify_signature(
                alg=alg, public_jwk=jwk, signing_input=signing_input, signature=signature)
        except KeyBackendError as exc:
            raise ProofError(f"could not verify {what}: {exc}") from exc
        if not ok:
            raise SignatureInvalid(f"{what} signature failed")

    def _check_temporal(self, claims: dict[str, Any]) -> None:
        now = int(time.time())
        exp = claims.get("exp")
        if isinstance(exp, (int, float)) and now > exp + self._leeway:
            raise ClaimsInvalid("token has expired")
        nbf = claims.get("nbf")
        if isinstance(nbf, (int, float)) and now + self._leeway < nbf:
            raise ClaimsInvalid("token is not yet valid")

    def _index_disclosures(self, disclosures: list[str], hash_name: str) -> dict[str, list]:
        by_digest: dict[str, list] = {}
        for disclosure in disclosures:
            try:
                parsed = json.loads(_b64url_decode(disclosure))
            except (ValueError, json.JSONDecodeError) as exc:
                raise SdJwtError("a disclosure is not valid base64url JSON") from exc
            if not isinstance(parsed, list) or len(parsed) not in (2, 3):
                raise SdJwtError("a disclosure must be a 2- or 3-element array")
            digest = disclosure_digest(disclosure, hash_name=hash_name)
            if digest in by_digest:
                raise SdJwtError("duplicate disclosure in presentation")
            by_digest[digest] = parsed
        return by_digest

    def _verify_key_binding(
        self,
        kb_jwt: str,
        issuer_jwt: str,
        disclosures: list[str],
        cnf: Any,
        *,
        hash_name: str,
        audience: str | None,
        nonce: str | None,
        required: bool,
    ) -> bool:
        if not kb_jwt:
            if required:
                raise ClaimsInvalid("key binding required but no KB-JWT present")
            return False
        header, claims, signing_input, signature = self._decode_jws(kb_jwt)
        if header.get("typ") != _KB_TYP:
            raise SdJwtError(f"KB-JWT typ must be {_KB_TYP!r}")
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:
            raise UnsupportedAlgorithm(f"KB-JWT algorithm {alg!r} is not permitted")
        if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
            raise ClaimsInvalid("no cnf.jwk in the issuer JWT for key binding")
        self._verify_signature(alg, cnf["jwk"], signing_input, signature, what="KB-JWT")

        if audience is not None and claims.get("aud") != audience:
            raise ClaimsInvalid("KB-JWT aud does not match")
        if nonce is not None and claims.get("nonce") != nonce:
            raise ClaimsInvalid("KB-JWT nonce does not match")
        presented = issuer_jwt + "~" + "".join(d + "~" for d in disclosures)
        expected = _b64url_encode(_HASHES[hash_name](presented.encode("ascii")).digest())
        if claims.get("sd_hash") != expected:
            raise ClaimsInvalid("KB-JWT sd_hash does not match the presented disclosures")
        return True
