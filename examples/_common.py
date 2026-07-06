"""
examples/_common.py — shared helpers for the runnable examples.

`did_key_ed25519()` / `did_key_p256()` generate a key and return it *already keyed*
to its did:key verification method, so an example can both sign with it and have the
pipeline's default resolver verify it — all offline, no DID plumbing.
"""
from __future__ import annotations

from openvc.multibase import encode_multibase

_MC_ED25519 = bytes([0xED, 0x01])     # multicodec ed25519-pub, unsigned-varint
_MC_P256 = bytes([0x80, 0x24])        # multicodec p256-pub (0x1200), unsigned-varint


def _did_key(raw_pubkey: bytes, multicodec: bytes):
    multibase = encode_multibase(multicodec + raw_pubkey)   # 'z' + base58btc(...)
    did = "did:key:" + multibase
    return did, f"{did}#{multibase}"                        # (did, verification method)


def did_key_ed25519():
    """(Ed25519SigningKey keyed to its did:key VM, did)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from openvc.keys import Ed25519SigningKey
    priv = ed25519.Ed25519PrivateKey.generate()
    did, vm = _did_key(Ed25519SigningKey(priv, kid="_").public_key_raw(), _MC_ED25519)
    return Ed25519SigningKey(priv, kid=vm), did


def did_key_p256():
    """(P256SigningKey keyed to its did:key VM, did)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from openvc.keys import P256SigningKey
    priv = ec.generate_private_key(ec.SECP256R1())
    raw = P256SigningKey(priv, kid="_").public_key_raw(compressed=True)
    did, vm = _did_key(raw, _MC_P256)
    return P256SigningKey(priv, kid=vm), did
