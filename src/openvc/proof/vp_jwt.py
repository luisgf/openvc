"""
openvc.proof.vp_jwt — Verifiable Presentation in JWT form (VP-JWT).

A **holder** wraps one or more credentials in a ``vp`` object and signs it: this
proves possession of the holder key and binds the presentation to a specific
verifier (``aud``) and a one-time challenge (``nonce``) so it cannot be replayed.

    holder  -> sign(credentials, holder_key, audience, nonce)   (a VP-JWT)
    verifier-> verify(vp, ..., audience, nonce)                 (holder sig + aud/nonce
                                                                 + every embedded VC)

Verification checks the holder signature (allow-listed ``{ES256, EdDSA}``), the
temporal claims, ``aud`` and ``nonce``, then **verifies each embedded credential
through the generic pipeline** (:func:`openvc.verify.verify_credential`) — so a VP
is only accepted when the holder is authentic *and* every credential in it is.

The holder key is resolved from the untrusted ``iss``/``kid`` via an injected
``resolver`` (as in the pipeline), or pinned with ``holder_key_jwk``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ._jws import parse_compact, sign_compact, verify_compact
from .vc_jwt import ClaimsInvalid, MalformedToken, SigningKey

DEFAULT_LEEWAY_S = 60
_VP_CONTEXT = "https://www.w3.org/ns/credentials/v2"


@dataclass(frozen=True)
class VerifiedPresentation:
    """A successfully verified VP-JWT."""
    holder: str | None
    credentials: tuple                 # a VerificationResult per embedded credential
    claims: dict[str, Any]             # the full JWT claim set (aud, nonce, vp, ...)
    vp: dict[str, Any]                 # the `vp` object


class VpJwtProofSuite:
    """Sign and verify VP-JWT holder presentations."""

    def __init__(self, *, leeway_s: int = DEFAULT_LEEWAY_S) -> None:
        self._leeway = leeway_s

    # -- untrusted inspection --------------------------------------------- #

    def peek_holder(self, vp_jwt: str) -> tuple[str | None, str | None]:
        """Return (holder, kid) WITHOUT verifying. UNTRUSTED — use only to select
        which key to resolve."""
        header, payload, _, _ = parse_compact(vp_jwt)
        vp = payload.get("vp")
        holder = payload.get("iss") or (vp.get("holder") if isinstance(vp, dict) else None)
        return (holder if isinstance(holder, str) else None), header.get("kid")

    # -- holder presentation ---------------------------------------------- #

    def sign(
        self,
        credentials: list,
        *,
        holder_key: SigningKey,
        audience: str,
        nonce: str,
        holder: str | None = None,
        expires_in_s: int | None = None,
    ) -> str:
        """Wrap *credentials* (VC-JWT / SD-JWT strings, or Data Integrity dicts) in a
        VP-JWT signed by *holder_key*, bound to *audience* and *nonce*."""
        now = int(time.time())
        holder_id = holder or holder_key.kid.split("#", 1)[0]
        vp = {
            "@context": [_VP_CONTEXT],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": list(credentials),
            "holder": holder_id,
        }
        payload: dict[str, Any] = {
            "iss": holder_id, "aud": audience, "nonce": nonce,
            "nbf": now, "iat": now, "vp": vp,
        }
        if expires_in_s is not None:
            payload["exp"] = now + expires_in_s
        header = {"alg": holder_key.alg, "typ": "JWT", "kid": holder_key.kid}
        return sign_compact(header, payload, signing_key=holder_key)

    # -- verification ------------------------------------------------------ #

    def verify(
        self,
        vp_jwt: str,
        *,
        audience: str,
        nonce: str,
        holder_key_jwk: dict[str, Any] | None = None,
        resolver: Any = None,
        expected_holder: str | None = None,
        require_holder_binding: bool = False,
        **credential_verify_kwargs: Any,
    ) -> VerifiedPresentation:
        """Verify a VP-JWT end to end: the holder signature, temporal claims,
        ``aud`` and ``nonce``, then every embedded credential via
        :func:`openvc.verify.verify_credential` (passing *resolver* and any
        *credential_verify_kwargs*, e.g. ``policy=`` / ``resolve_status_list=``).

        The holder key is *holder_key_jwk* if given, else resolved from the peeked
        ``iss``/``kid`` through *resolver*.

        **Holder binding.** By default (``require_holder_binding=False``) this proves
        the *holder* signed the presentation and each credential is *valid*, but does
        NOT require the credentials to have been issued to that holder — a holder can
        legitimately present a third party's credential. Set
        ``require_holder_binding=True`` to additionally require every embedded
        credential's ``credentialSubject.id`` to equal the holder, so a presenter
        cannot pass off a credential issued to someone else as their own. (Off by
        default to match ``SdJwtVcProofSuite``'s ``require_key_binding``.) The
        holder's identity is authenticated only in resolver mode (the key is
        resolved *from* ``iss``); with a **pinned** ``holder_key_jwk`` the ``iss``
        is signer-supplied, so *expected_holder* must be given to bind and to trust
        the returned holder. *expected_holder*, if set, requires ``iss`` to equal
        it. *audience* and *nonce* are required and must be non-empty — VP-JWT has
        no unbound mode."""
        if not audience or not nonce:
            raise ClaimsInvalid("VP-JWT verify requires a non-empty audience and nonce")

        pinned = holder_key_jwk is not None
        if holder_key_jwk is None:
            holder_key_jwk = self._resolve_holder_key(vp_jwt, resolver)
        header, claims = verify_compact(vp_jwt, public_key_jwk=holder_key_jwk)

        self._check_temporal(claims)
        self._check_audience(claims.get("aud"), audience)
        if claims.get("nonce") != nonce:
            raise ClaimsInvalid("nonce does not match the expected challenge")

        vp = claims.get("vp")
        if not isinstance(vp, dict):
            raise ClaimsInvalid("VP-JWT has no `vp` object")
        holder = claims.get("iss") or vp.get("holder")
        if not isinstance(holder, str) or not holder:
            raise ClaimsInvalid("VP-JWT has no holder (iss / vp.holder)")
        if vp.get("holder") and vp.get("holder") != holder:
            raise ClaimsInvalid("vp.holder does not match iss")
        if expected_holder is not None and holder != expected_holder:
            raise ClaimsInvalid(f"holder {holder!r} != expected {expected_holder!r}")

        # binding is sound only against an AUTHENTICATED holder: resolver mode binds
        # iss to the key; a pinned key does not, so it needs expected_holder (checked
        # up front, before the cascade even runs)
        if require_holder_binding and pinned and expected_holder is None:
            raise ClaimsInvalid(
                "require_holder_binding with a pinned holder key needs "
                "expected_holder to authenticate the presenter")

        from ..verify import verify_credential
        raw = vp.get("verifiableCredential", [])
        entries = [raw] if isinstance(raw, (str, dict)) else list(raw)
        results = tuple(
            verify_credential(entry, resolver=resolver, **credential_verify_kwargs)
            for entry in entries)

        if require_holder_binding:
            for result in results:
                if not result.subject or result.subject != holder:
                    raise ClaimsInvalid(
                        f"credential subject {result.subject!r} is not the holder "
                        f"{holder!r} (holder binding required)")

        return VerifiedPresentation(
            holder=holder, credentials=results, claims=claims, vp=vp)

    # -- internals --------------------------------------------------------- #

    def _resolve_holder_key(self, vp_jwt: str, resolver: Any) -> dict[str, Any]:
        if resolver is None:
            raise ClaimsInvalid("VP-JWT verify needs a holder_key_jwk or a resolver")
        holder, kid = self.peek_holder(vp_jwt)
        if not holder:
            raise MalformedToken("VP-JWT has no holder (iss / vp.holder) to resolve")
        from ..verify import KeyResolutionFailed, _resolve_jose_key
        try:
            return _resolve_jose_key(resolver, holder, kid)
        except KeyResolutionFailed as exc:
            raise ClaimsInvalid(f"could not resolve holder key: {exc}") from exc

    def _check_temporal(self, claims: dict[str, Any]) -> None:
        now = int(time.time())
        exp = claims.get("exp")
        if exp is not None:
            if isinstance(exp, bool) or not isinstance(exp, (int, float)):
                raise ClaimsInvalid("exp claim must be a numeric timestamp")
            if now > exp + self._leeway:
                raise ClaimsInvalid("presentation has expired")
        nbf = claims.get("nbf")
        if nbf is not None:
            if isinstance(nbf, bool) or not isinstance(nbf, (int, float)):
                raise ClaimsInvalid("nbf claim must be a numeric timestamp")
            if now + self._leeway < nbf:
                raise ClaimsInvalid("presentation is not yet valid")

    @staticmethod
    def _check_audience(aud: Any, expected: str) -> None:
        ok = aud == expected or (isinstance(aud, list) and expected in aud)
        if not ok:
            raise ClaimsInvalid(f"aud {aud!r} != expected verifier {expected!r}")
