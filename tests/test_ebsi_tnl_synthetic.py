"""
tests/test_ebsi_tnl_synthetic.py — the Trusted Nodes List verifier against CHAINS WE SIGN
(issue #319, ADR-0009 D2/D3).

The recorded chain (test_ebsi_tnl_golden.py) has exactly one version of each document and
one profile of OpenPGP. Everything that needs a different signed document lives here: a
test-only in-memory OpenPGP writer (``cryptography`` only, throwaway keys, no bytes
committed — they differ on every run and no test pins them) builds valid chains and then
deliberately broken ones.

Because the reader never verifies a self-signature, the writer emits structurally valid
self- and binding signatures with arbitrary values; only the detached signatures over the
two JSON documents are real. ``tests/`` is not a package, so this writer is not shared.
Every check that a hostile input is refused asserts the EXACT class (``type(exc) is X``),
so a test cannot pass on an earlier, unrelated failure.
"""
from __future__ import annotations

import base64
import copy
import functools
import hashlib
import json
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from openvc import _json
from openvc_ebsi import _openpgp
from openvc_ebsi import nodes as nodes_mod
from openvc_ebsi.errors import (
    NodeListConfigError,
    NodeListEnvironmentMissing,
    NodeListError,
    NodeListExpired,
    NodeListMalformed,
    NodeListNotYetValid,
    NodeListRollback,
    NodeListSignatureError,
    NodeListStale,
    NodeListThresholdError,
    OpenPgpError,
)
from openvc_ebsi.nodes import Accepted, Anchor, verify_node_list

FIX = Path(__file__).parent / "fixtures" / "ebsi" / "tnl"
SYN_NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
P256 = bytes.fromhex("2a8648ce3d030107")
PREFIX = {"pilot": "https://api-pilot.ebsi.", "preprod": "https://api-preprod.ebsi.",
          "prod": "https://api.ebsi."}


# ======================================================================================
# the writer: v4 ECDSA/P-256/SHA-256 OpenPGP, old-format packets, ~80 lines
# ======================================================================================
def mpi(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return value.bit_length().to_bytes(2, "big") + raw


def mpi_raw(raw: bytes) -> bytes:
    """An MPI whose value is the big-endian *raw* (for a point whose first octet is 0x04)."""
    return (8 * (len(raw) - 1) + raw[0].bit_length()).to_bytes(2, "big") + raw


def pkt(tag: int, body: bytes, kind: int | None = None) -> bytes:
    """An old-format packet; *kind* picks the length type (0: 1, 1: 2, 2: 4 octets)."""
    if kind is None:
        kind = 0 if len(body) < 256 else 1 if len(body) < 65536 else 2
    return bytes([0x80 | tag << 2 | kind]) + len(body).to_bytes((1, 2, 4)[kind], "big") + body


def sub(kind: int, data: bytes, *, critical: bool = False, form: int | None = None) -> bytes:
    """A subpacket; *form* forces the 1-, 2- or 5-octet length encoding."""
    n = len(data) + 1
    form = form or (1 if n < 192 else 2 if n < 8384 else 5)
    assert (form == 1 and n < 192) or (form == 2 and 192 <= n < 8384) or form == 5, \
        "length does not fit that encoding"
    head = (bytes([n]) if form == 1
            else bytes([((n - 192) >> 8) + 192, (n - 192) & 0xFF]) if form == 2
            else b"\xff" + n.to_bytes(4, "big"))
    return head + bytes([kind | (0x80 if critical else 0)]) + data


class Key:
    """A throwaway OpenPGP v4 ECDSA key: its packet body and v4 fingerprint."""

    def __init__(self, created: int = 1_790_000_000, *, oid: bytes = P256, algo: int = 19,
                 sk: ec.EllipticCurvePrivateKey | None = None, point: bytes | None = None,
                 version: int = 4) -> None:
        self.sk = sk or ec.generate_private_key(ec.SECP256R1())
        self.point = point or self.sk.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        self.created = created
        self.body = (bytes([version]) + created.to_bytes(4, "big") + bytes([algo, len(oid)])
                     + oid + mpi_raw(self.point))
        self.fp = hashlib.sha1(b"\x99" + len(self.body).to_bytes(2, "big")
                               + self.body).hexdigest().upper()


def sig_body(key: Key, doc: bytes, *, sig_type: int = 0, version: int = 4, algo: int = 19,
             hash_id: int = 8, issuer: str | None = None, hashed: bytes | None = None,
             extra_hashed: bytes = b"", unhashed: bytes | None = None,
             r_s: tuple[int, int] | None = None) -> bytes:
    fp = issuer or key.fp
    if hashed is None:
        hashed = (sub(33, b"\x04" + bytes.fromhex(fp)) + sub(2, (1_790_000_100).to_bytes(4, "big"))
                  + extra_hashed)
    if unhashed is None:
        unhashed = sub(16, bytes.fromhex(fp)[-8:])
    head = bytes([version, sig_type, algo, hash_id]) + len(hashed).to_bytes(2, "big") + hashed
    digest = hashlib.sha256(doc + head + b"\x04\xff" + len(head).to_bytes(4, "big")).digest()
    r, s = r_s or utils.decode_dss_signature(
        key.sk.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    return head + len(unhashed).to_bytes(2, "big") + unhashed + digest[:2] + mpi(r) + mpi(s)


def sig_packet(key: Key, doc: bytes, kind: int | None = None, **kw: Any) -> bytes:
    return pkt(2, sig_body(key, doc, **kw), kind)


def crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor(data: bytes, *, crc: bool = True) -> str:
    b64 = base64.b64encode(data).decode()
    lines = ["-----BEGIN PGP PUBLIC KEY BLOCK-----", ""]
    lines += [b64[i:i + 64] for i in range(0, len(b64), 64)]
    if crc:
        lines.append("=" + base64.b64encode(crc24(data).to_bytes(3, "big")).decode())
    lines.append("-----END PGP PUBLIC KEY BLOCK-----")
    return "\n".join(lines) + "\n"


def block(key: Key, *extra: bytes, self_sig: bytes | None = None) -> str:
    """An armored custodian block: primary key, a User ID, a structurally valid self-signature
    (never verified by the reader) and any *extra* packets."""
    cert = self_sig if self_sig is not None else sig_body(key, b"", sig_type=0x13)
    return armor(pkt(6, key.body) + pkt(13, b"Throwaway Custodian") + pkt(2, cert)
                 + b"".join(extra))


# ======================================================================================
# chains
# ======================================================================================
ANCHOR = Key(1_790_000_001)
CUST = [Key(1_790_000_010 + i) for i in range(4)]
SYN_ANCHOR = Anchor(ANCHOR.fp, "P-256", ANCHOR.point)


def nodes_for(env: str, count: int) -> list[dict[str, str]]:
    return [{"url": f"{PREFIX[env]}n{i}.example.org", "country": "BE", "organisation": f"Org {i}"}
            for i in range(count)]


def make_tnl(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "version": 4, "keysVersion": 1, "issued": "2026-11-01T00:00:00Z",
        "expires": "2026-12-01T00:00:00Z",
        "environments": {"pilot": nodes_for("pilot", 2), "preprod": nodes_for("preprod", 1),
                         "prod": nodes_for("prod", 2)}}
    doc.update(over)
    return doc


def encode(doc: Any) -> bytes:
    return (json.dumps(doc, indent=2) + "\n").encode()


def make_keys(custodians: list[Key], threshold: Any, version: int = 1,
              blocks: dict[int, str] | None = None) -> dict[str, Any]:
    blocks = blocks or {}
    return {"version": version, "threshold": threshold,
            "keys": [{"fingerprint": c.fp, "publicKey": blocks.get(i, block(c))}
                     for i, c in enumerate(custodians)]}


@dataclass(frozen=True)
class Bundle:
    keys: bytes
    keys_sig: bytes
    tnl: bytes
    tnl_sig: bytes
    custodians: tuple[Key, ...]

    def call(self, **over: Any) -> Any:
        args: dict[str, Any] = dict(
            tnl=self.tnl, tnl_sig=self.tnl_sig, keys=self.keys, keys_sig=self.keys_sig,
            environment="prod", now=SYN_NOW, last_accepted_list=None, last_accepted_keys=None,
            anchor=SYN_ANCHOR)
        args.update(over)
        return verify_node_list(**args)

    def with_tnl(self, raw: bytes, signers: list[Key] | None = None) -> Bundle:
        """The same chain with *raw* as the node list, signed by *signers*."""
        who = list(self.custodians) if signers is None else signers
        return replace(self, tnl=raw, tnl_sig=b"".join(sig_packet(k, raw) for k in who))

    def with_keys(self, raw: bytes) -> Bundle:
        return replace(self, keys=raw, keys_sig=sig_packet(ANCHOR, raw))


_DEFAULT = object()


def bundle(custodians: list[Key] | None = None, threshold: Any = _DEFAULT, *, keys_version: int = 1,
           tnl_doc: dict[str, Any] | None = None, signers: list[Key] | None = None,
           blocks: dict[int, str] | None = None) -> Bundle:
    cust = custodians if custodians is not None else CUST[:2]
    keys = encode(make_keys(cust, len(cust) if threshold is _DEFAULT else threshold,
                            keys_version, blocks))
    tnl = encode(tnl_doc or make_tnl())
    who = cust if signers is None else signers
    return Bundle(keys, sig_packet(ANCHOR, keys), tnl,
                  b"".join(sig_packet(k, tnl) for k in who), tuple(cust))


def raises(exc: type[Exception], fn: Callable[[], Any]) -> Exception:
    """Run *fn*; require EXACTLY the class *exc*, so a subclass or an earlier failure of a
    different kind cannot satisfy the assertion."""
    with pytest.raises(Exception) as info:
        fn()
    assert type(info.value) is exc, f"{type(info.value).__name__}: {info.value}"
    return info.value


# ======================================================================================
# the writer produces real OpenPGP, and the happy chain verifies
# ======================================================================================
def test_the_writer_chain_verifies_for_every_environment() -> None:
    b = bundle()
    for env, count in (("pilot", 2), ("preprod", 1), ("prod", 2)):
        r = b.call(environment=env)
        assert len(r.nodes) == count and r.environment == env
        assert r.hosts == frozenset(f"{PREFIX[env][8:]}n{i}.example.org" for i in range(count))
    assert r.accepted_keys == Accepted(1, hashlib.sha256(b.keys).hexdigest())


def test_the_writer_fingerprint_matches_the_readers_recomputation() -> None:
    for key in (ANCHOR, *CUST):
        assert _openpgp.read_public_key_block(block(key)).fingerprint == key.fp


@pytest.mark.parametrize("kind", [0, 1, 2])
def test_every_old_format_length_type_is_read(kind: int) -> None:
    keys = encode(make_keys(CUST[:2], 2))
    tnl = encode(make_tnl())
    b = Bundle(keys, sig_packet(ANCHOR, keys, kind), tnl,
               b"".join(sig_packet(k, tnl, kind) for k in CUST[:2]), tuple(CUST[:2]))
    assert b.call().version == 4
    # and in a key block: the same packets framed with the longer lengths
    blk = armor(pkt(6, CUST[0].body, kind) + pkt(13, b"uid", kind))
    assert _openpgp.read_public_key_block(blk).fingerprint == CUST[0].fp


@pytest.mark.parametrize("form", [1, 2, 5])
def test_every_subpacket_length_encoding_is_read(form: int) -> None:
    # the 2-octet form can only express 192..8383, so it carries a long (ignored) subpacket
    filler = sub(20, bytes(300), form=form) if form != 1 else sub(20, bytes(8), form=1)
    hashed = (sub(33, b"\x04" + bytes.fromhex(CUST[0].fp), form=1 if form == 2 else form)
              + sub(2, (1_790_000_100).to_bytes(4, "big"), form=1 if form == 2 else form) + filler)
    sigs = _openpgp.read_signatures(sig_packet(CUST[0], b"d", hashed=hashed))
    assert sigs[0].signer == CUST[0].fp


# ======================================================================================
# thresholds and signer attribution
# ======================================================================================
@pytest.mark.parametrize("n,threshold,signers,ok", [
    (2, 2, [0, 1], True), (3, 2, [0, 2], True), (3, 3, [0, 1, 2], True), (4, 2, [3, 1], True),
    (3, 2, [0], False), (3, 3, [0, 1], False), (2, 2, [], False), (2, 2, [1], False)])
def test_thresholds(n: int, threshold: int, signers: list[int], ok: bool) -> None:
    b = bundle(CUST[:n], threshold, signers=[CUST[i] for i in signers])
    if ok:
        assert b.call().version == 4
    elif signers:
        raises(NodeListThresholdError, b.call)
    else:                                                   # no signature at all: not a file
        raises(OpenPgpError, lambda: b.with_tnl(b.tnl, []).call())


def test_threshold_of_one_needs_min_threshold_none() -> None:
    b = bundle(CUST[:1], 1)
    err = raises(NodeListThresholdError, b.call)             # the default minimum is 2
    assert "below the minimum 2" in str(err)
    assert b.call(min_threshold=None).version == 4
    assert b.call(min_threshold=1).version == 4


@pytest.mark.parametrize("threshold", [0, -1, True, False, 2.0, 2.5, "2", None, [2], 4, 10 ** 30])
def test_a_threshold_outside_one_to_custodians_is_malformed(threshold: Any) -> None:
    b = bundle(CUST[:3], threshold, signers=CUST[:3])
    raises(NodeListMalformed, b.call)


def test_a_huge_threshold_does_not_lengthen_the_message() -> None:
    """The integer is shown through safe_repr (a 64-bit int as itself, anything larger by its
    type), not formatted whole: a 4000-digit integer would otherwise be a 4 KB message."""
    err = raises(NodeListMalformed, bundle(CUST[:3], 10 ** 4000, signers=CUST[:3]).call)
    assert "threshold" in str(err) and len(str(err)) < 200, len(str(err))
    err = raises(NodeListMalformed, bundle(CUST[:3], 2 ** 63 - 1, signers=CUST[:3]).call)
    assert "9223372036854775807" in str(err)


def test_a_custodian_who_signs_twice_counts_once() -> None:
    b = bundle(CUST[:2], 2, signers=[CUST[0], CUST[0]])
    raises(NodeListThresholdError, b.call)


def test_a_signing_subkey_is_not_a_signer_identity() -> None:
    """The custodian's primary is what the list names; a signature whose hashed issuer is
    the SUBKEY's fingerprint is an unknown signer, so the count stays below the threshold."""
    sub_key = Key(1_790_000_500)
    primary = CUST[0]
    extra = pkt(14, sub_key.body)
    b = bundle(CUST[:2], 2, signers=[CUST[1]], blocks={0: block(primary, extra)})
    forged = sig_packet(sub_key, b.tnl)                       # hashed issuer = the subkey's fp
    assert _openpgp.read_signatures(forged)[0].signer == sub_key.fp
    raises(NodeListThresholdError, lambda: replace(b, tnl_sig=b.tnl_sig + forged).call())


def test_an_issuer_in_the_unhashed_area_only_is_an_unknown_signer() -> None:
    fp = CUST[0].fp
    only_unhashed = pkt(2, sig_body(
        CUST[0], b"", hashed=sub(2, b"\x00\x00\x00\x01"),
        unhashed=sub(33, b"\x04" + bytes.fromhex(fp)) + sub(16, bytes.fromhex(fp)[-8:])))
    assert _openpgp.read_signatures(only_unhashed)[0].signer is None
    b = bundle(CUST[:2], 2, signers=[CUST[1]])
    raises(NodeListThresholdError, lambda: replace(b, tnl_sig=b.tnl_sig + only_unhashed).call())
    # and the same CUSTODIAN identified only by the unhashed key ID cannot make up the count
    b2 = bundle(CUST[:1], 1)
    raises(NodeListThresholdError,
           lambda: replace(b2, tnl_sig=only_unhashed).call(min_threshold=None))


def test_an_issuer_claim_cannot_be_forged_without_the_key() -> None:
    """Custodian 1 signs while naming custodian 0 in the hashed area: custodian 0's key
    does not verify it, so the file is rejected rather than counted for either."""
    b = bundle(CUST[:2], 2, signers=[CUST[0]])
    forged = sig_packet(CUST[1], b.tnl, issuer=CUST[0].fp)
    both = forged + sig_packet(CUST[1], b.tnl)
    raises(NodeListSignatureError, lambda: replace(b, tnl_sig=both).call())


def test_a_stranger_with_garbage_values_is_skipped_and_never_verified(
        monkeypatch: pytest.MonkeyPatch) -> None:
    b = bundle()
    stranger = Key(1_790_000_900)
    garbage = pkt(2, sig_body(stranger, b.tnl, r_s=(2 ** 255 + 12345, 2 ** 255 + 999)))
    calls: list[str] = []
    real = _openpgp.verify

    def counting(signature: Any, document: bytes, key: Any) -> bool:
        calls.append(key.fingerprint)
        return real(signature, document, key)

    monkeypatch.setattr(_openpgp, "verify", counting)
    assert replace(b, tnl_sig=garbage + b.tnl_sig).call().version == 4
    custodian_calls = [fp for fp in calls if fp != ANCHOR.fp]    # the anchor checked the key list
    assert sorted(custodian_calls) == sorted(c.fp for c in CUST[:2])   # the stranger cost no ECDSA


def test_one_bad_signature_by_an_allowed_key_rejects_the_whole_file() -> None:
    b = bundle()
    bad = sig_packet(CUST[0], b.tnl, r_s=(2 ** 200 + 7, 2 ** 200 + 11))
    raises(NodeListSignatureError, lambda: replace(b, tnl_sig=b.tnl_sig + bad).call())


def test_the_anchor_cannot_sign_the_node_list_and_a_custodian_cannot_sign_the_key_list() -> None:
    b = bundle()
    raises(NodeListThresholdError, lambda: replace(b, tnl_sig=sig_packet(ANCHOR, b.tnl)).call())
    raises(NodeListSignatureError,
           lambda: replace(b, keys_sig=sig_packet(CUST[0], b.keys)).call())


def test_a_second_anchor_signature_must_also_verify() -> None:
    b = bundle()
    bad = sig_packet(ANCHOR, b.keys, r_s=(3, 5))
    raises(NodeListSignatureError, lambda: replace(b, keys_sig=b.keys_sig + bad).call())
    assert replace(b, keys_sig=b.keys_sig + b.keys_sig).call().version == 4


# ======================================================================================
# custodian key blocks
# ======================================================================================
def test_a_listed_fingerprint_that_is_not_the_keys_is_malformed() -> None:
    doc = make_keys(CUST[:2], 2)
    doc["keys"][0]["fingerprint"] = CUST[1].fp
    b = bundle().with_keys(encode(doc))
    raises(NodeListMalformed, b.call)


def test_a_duplicate_custodian_is_malformed() -> None:
    doc = make_keys([CUST[0], CUST[0]], 2)
    raises(NodeListMalformed, lambda: bundle().with_keys(encode(doc)).call())


def test_the_same_key_listed_under_two_creation_times_is_one_custodian() -> None:
    """Two fingerprints, one key: a signer could name either in the hashed area and be
    counted twice. The point is refused as well as the fingerprint."""
    twin = Key(1_790_000_077, sk=CUST[0].sk)
    assert twin.fp != CUST[0].fp and twin.point == CUST[0].point
    doc = make_keys([CUST[0], twin], 2)
    err = raises(NodeListMalformed, lambda: bundle().with_keys(encode(doc)).call())
    assert "repeats a custodian" in str(err)


def test_subkeys_user_ids_and_unverified_self_signatures_are_skipped() -> None:
    # a subkey body that is not even a valid ECDH key: skipped, algorithm not interpreted
    odd_subkey = pkt(14, bytes([4]) + bytes(4) + bytes([18, 8]) + P256 + b"\x00\x08\x01")
    many = [pkt(13, b"another user id %d" % i) for i in range(3)]
    b = bundle(blocks={0: block(CUST[0], odd_subkey, *many)})
    assert b.call().version == 4
    # an unknown CRITICAL subpacket in a self-signature is not interpreted (it is not verified)
    # (GnuPG 2.5.24 drops such a key; this is a stated divergence, docs/audit/assurance.md s.4)
    crit = sig_body(CUST[1], b"", sig_type=0x13, extra_hashed=sub(100, b"x", critical=True))
    assert bundle(blocks={1: block(CUST[1], self_sig=crit)}).call().version == 4
    # and neither is a missing or a repeated creation time, which a SIGNATURE FILE must not have
    bare = sig_body(CUST[1], b"", sig_type=0x13, hashed=b"")
    assert bundle(blocks={1: block(CUST[1], self_sig=bare)}).call().version == 4
    twice = sig_body(CUST[1], b"", sig_type=0x13, extra_hashed=CTIME)
    assert bundle(blocks={1: block(CUST[1], self_sig=twice)}).call().version == 4


def _block_packets(*parts: bytes) -> str:
    return armor(b"".join(parts))


KEY0 = pkt(6, CUST[0].body)


@pytest.mark.parametrize("name,armored", [
    ("revocation 0x20", block(CUST[0], pkt(2, sig_body(CUST[0], b"", sig_type=0x20)))),
    ("subkey revocation 0x28", block(CUST[0], pkt(2, sig_body(CUST[0], b"", sig_type=0x28)))),
    ("cert revocation 0x30", block(CUST[0], pkt(2, sig_body(CUST[0], b"", sig_type=0x30)))),
    ("key expiration 9", block(CUST[0], self_sig=sig_body(
        CUST[0], b"", sig_type=0x13, extra_hashed=sub(9, b"\x00\x01\x00\x00")))),
    ("signature expiration 3", block(CUST[0], self_sig=sig_body(
        CUST[0], b"", sig_type=0x13, extra_hashed=sub(3, b"\x00\x01\x00\x00")))),
    ("critical key expiration", block(CUST[0], self_sig=sig_body(
        CUST[0], b"", sig_type=0x13, extra_hashed=sub(9, b"\x00\x01\x00\x00", critical=True)))),
    ("v3 self-signature", block(CUST[0], self_sig=b"\x03" + bytes(20))),
    ("v5 self-signature", block(CUST[0], self_sig=sig_body(CUST[0], b"", version=5))),
    ("self-signature cut short", block(CUST[0], self_sig=b"\x04\x13")),
    ("self-signature hashed area past packet", block(
        CUST[0], self_sig=bytes([4, 0x13, 19, 8]) + b"\xff\xff" + b"\x00" * 10)),
    ("secret key tag 5", _block_packets(KEY0, pkt(5, b"x"))),
    ("secret subkey tag 7", _block_packets(KEY0, pkt(7, b"x"))),
    ("trust tag 12", _block_packets(KEY0, pkt(12, b"x"))),
    ("attribute tag 17", _block_packets(KEY0, pkt(17, b"x"))),
    ("reserved tag 0", _block_packets(KEY0, pkt(0, b"x"))),
    ("second primary key", _block_packets(KEY0, pkt(6, CUST[1].body))),
    ("no primary key", _block_packets(pkt(13, b"uid"), KEY0)),
    ("empty packet stream", armor(b"")),
    ("trailing byte", armor(KEY0 + b"\x00")),
    ("trailing garbage packet header", armor(KEY0 + b"\x99")),
    ("new-format header", armor(bytes([0xC0 | 6, len(CUST[0].body)]) + CUST[0].body)),
    # 0xD8 is a NEW-format header (tag 24); read as an old-format header it says tag 6, so a
    # reader that ignored bit 6 would take this packet for a primary key
    ("new-format header that an old-format reader takes for tag 6",
     armor(bytes([0xD8, len(CUST[0].body)]) + CUST[0].body)),
    ("partial length", armor(bytes([0xC0 | 6, 0xE1]) + CUST[0].body)),
    ("indefinite length", armor(bytes([0x80 | 6 << 2 | 3]) + CUST[0].body)),
    ("high bit clear", armor(bytes([0x40]) + b"x")),
    ("length past the end", armor(KEY0[:-5])),
    ("length lies by one", armor(bytes([KEY0[0], KEY0[1] + 1]) + KEY0[2:])),
])
def test_hostile_key_blocks_are_open_pgp_errors(name: str, armored: str) -> None:
    raises(OpenPgpError, lambda: _openpgp.read_public_key_block(armored))
    b = bundle(blocks={0: armored})                       # authenticated, so it IS reached
    raises(OpenPgpError, b.call)


def _key_variant(**kw: Any) -> str:
    key = Key(1_790_000_300, **kw)
    return armor(pkt(6, key.body))


COMPRESSED = b"\x02" + CUST[0].point[1:33]
OFF_CURVE = b"\x04" + CUST[0].point[1:33] + bytes((CUST[0].point[64] ^ 1,)).rjust(32, b"\x00")


@pytest.mark.parametrize("name,armored", [
    ("compressed point", _key_variant(point=COMPRESSED)),
    ("off-curve point", _key_variant(point=OFF_CURVE)),
    ("point too short", _key_variant(point=CUST[0].point[:-1])),
    ("point too long", _key_variant(point=CUST[0].point + b"\x00")),
    ("native point 0x40", _key_variant(point=b"\x40" + CUST[0].point[1:])),
    ("P-384 oid", _key_variant(oid=bytes.fromhex("2b81040022"))),
    ("secp256k1 oid", _key_variant(oid=bytes.fromhex("2b8104000a"))),
    ("ed25519 oid", _key_variant(oid=bytes.fromhex("2b06010401da470f01"))),
    ("empty oid", _key_variant(oid=b"")),
    ("RSA algorithm", _key_variant(algo=1)),
    ("EdDSA algorithm", _key_variant(algo=22)),
    ("ECDH algorithm", _key_variant(algo=18)),
    ("v3 key", _key_variant(version=3)),
    ("v5 key", _key_variant(version=5)),
    ("v6 key", _key_variant(version=6)),
])
def test_key_material_outside_the_profile_is_an_open_pgp_error(name: str, armored: str) -> None:
    raises(OpenPgpError, lambda: _openpgp.read_public_key_block(armored))


@pytest.mark.parametrize("mpi_bytes", [
    b"\x00\x00",                                              # zero bits, no data
    b"\x02\x08" + CUST[0].point,                              # bit count lies (520, value is 515)
    b"\x02\x02" + CUST[0].point,                              # bit count one short
    b"\xff\xff" + CUST[0].point,                              # 0xFFFF bits
    b"\x02\x08\x00" + CUST[0].point,                          # non-minimal: leading zero octet
    b"\x02\x03" + CUST[0].point[:30],                         # truncated: runs past the packet
    b"\x02",                                                  # the bit count itself cut short
    b"",
])
def test_lying_or_truncated_point_mpis_are_open_pgp_errors(mpi_bytes: bytes) -> None:
    body = bytes([4]) + bytes(4) + bytes([19, 8]) + P256 + mpi_bytes
    raises(OpenPgpError, lambda: _openpgp.read_public_key_block(armor(pkt(6, body))))


@pytest.mark.parametrize("armored,why", [
    ("", "empty"),
    ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----\n", "no data"),
    (armor(KEY0).replace("\n\n", "\nVersion: x\n\n", 1), "armor header line"),
    (armor(KEY0).replace("\n", "\r\n"), "CRLF"),
    (armor(KEY0).rstrip("\n"), "no final newline is fine"),     # accepted: one final LF optional
    (armor(KEY0) + "\n", "two final newlines"),
    (armor(KEY0).replace("PUBLIC", "PRIVATE"), "wrong block type"),
    (" " + armor(KEY0), "leading space"),
    (armor(KEY0).replace("-----END", " -----END"), "END with a space"),
    (armor(KEY0, crc=False).replace("\n-----END", "\n=AAAA\n-----END"), "wrong CRC"),
    (armor(KEY0).replace("=", "==", 1), "malformed CRC line"),
    ("\N{LATIN SMALL LETTER E WITH ACUTE}" + armor(KEY0), "non-ASCII"),
    (armor(KEY0).replace("A", "*", 1), "not base64"),
    ("x" * 20000, "over the armor cap"),
    (armor(b"\x00" * (_openpgp.MAX_KEY_BLOCK_BYTES + 1)), "over the dearmored cap"),
])
def test_armor_outside_the_recorded_shape_is_refused(armored: str, why: str) -> None:
    if why == "no final newline is fine":
        assert _openpgp.read_public_key_block(armored).fingerprint == CUST[0].fp
        return
    raises(OpenPgpError, lambda: _openpgp.read_public_key_block(armored))


def test_armor_without_a_crc_line_is_accepted_and_with_one_it_is_checked() -> None:
    assert _openpgp.read_public_key_block(armor(KEY0, crc=False)).fingerprint == CUST[0].fp
    assert _openpgp.crc24(KEY0) == crc24(KEY0)                        # two implementations agree


def test_a_non_string_public_key_member_is_an_open_pgp_error() -> None:
    for bad in (None, 5, ["x"], {"a": 1}, True):
        doc = make_keys(CUST[:2], 2)
        doc["keys"][0]["publicKey"] = bad
        raises(OpenPgpError, lambda: bundle().with_keys(encode(doc)).call())


# ======================================================================================
# the detached-signature reader
# ======================================================================================
R256, S256 = 2 ** 255 + 0x1234, 2 ** 255 + 0x5678      # both exactly 256 bits: 34-octet MPIs


def _sig(**kw: Any) -> bytes:
    return sig_packet(CUST[0], b"doc", **{"r_s": (R256, S256), **kw})


CTIME = sub(2, (1_790_000_100).to_bytes(4, "big"))     # the writer's own creation time


def _signer_hashed(*extra: bytes, fp: str = CUST[0].fp) -> bytes:
    return sub(33, b"\x04" + bytes.fromhex(fp)) + b"".join(extra)


GOOD = _sig()


@pytest.mark.parametrize("name,data", [
    ("SHA-1", _sig(hash_id=2)), ("SHA-384", _sig(hash_id=9)), ("SHA-512", _sig(hash_id=10)),
    ("SHA-224", _sig(hash_id=11)), ("RSA", _sig(algo=1)), ("EdDSA", _sig(algo=22)),
    ("ECDH", _sig(algo=18)), ("DSA", _sig(algo=17)),
    ("v3", pkt(2, b"\x03" + bytes(18))), ("v5", _sig(version=5)), ("v6", _sig(version=6)),
    ("text signature", _sig(sig_type=0x01)), ("canonical text", _sig(sig_type=0x02)),
    ("certification 0x10", _sig(sig_type=0x10)), ("binding 0x18", _sig(sig_type=0x18)),
    ("revocation 0x20", _sig(sig_type=0x20)), ("subkey revocation 0x28", _sig(sig_type=0x28)),
    ("cert revocation 0x30", _sig(sig_type=0x30)), ("timestamp 0x40", _sig(sig_type=0x40)),
    ("signature expiration 3", _sig(extra_hashed=sub(3, b"\x00\x01\x00\x00"))),
    ("key expiration 9", _sig(extra_hashed=sub(9, b"\x00\x01\x00\x00"))),
    ("expiration hidden by critical bit", _sig(extra_hashed=sub(3, bytes(4), critical=True))),
    ("unknown critical subpacket", _sig(extra_hashed=sub(100, b"x", critical=True))),
    ("critical notation data", _sig(extra_hashed=sub(20, bytes(8), critical=True))),
    ("critical key flags", _sig(extra_hashed=sub(27, b"\x03", critical=True))),
    ("two issuer fingerprints", _sig(extra_hashed=sub(33, b"\x04" + bytes.fromhex(CUST[1].fp)))),
    ("issuer fingerprint v5", _sig(hashed=sub(33, b"\x05" + bytes.fromhex(CUST[0].fp)) + CTIME)),
    ("issuer fingerprint 20 octets",
     _sig(hashed=sub(33, b"\x04" + bytes.fromhex(CUST[0].fp)[:19]) + CTIME)),
    ("issuer fingerprint 32 octets", _sig(hashed=sub(33, b"\x06" + bytes(32)) + CTIME)),
    # RFC 4880 section 5.2.3.4: a signature carries exactly one creation time in its hashed
    # area; GnuPG 2.5.24 rejects a signature without one
    ("no creation time", _sig(hashed=_signer_hashed())),
    ("two creation times", _sig(extra_hashed=CTIME)),
    ("creation time of 0 octets", _sig(hashed=_signer_hashed(sub(2, b"")))),
    ("creation time of 2 octets", _sig(hashed=_signer_hashed(sub(2, b"\x00\x01")))),
    ("creation time of 5 octets", _sig(hashed=_signer_hashed(sub(2, bytes(5))))),
    ("creation time only in the unhashed area",
     _sig(hashed=_signer_hashed(), unhashed=sub(16, bytes(8)) + CTIME)),
    # nothing in the unhashed area is interpreted, so a critical-bit subpacket there is one
    # the reader cannot honour; GnuPG 2.5.24 calls an unknown one a bad signature
    ("unhashed critical unknown subpacket", _sig(unhashed=sub(100, b"x", critical=True))),
    ("unhashed critical issuer key id", _sig(unhashed=sub(16, bytes(8), critical=True))),
    ("unhashed critical creation time", _sig(unhashed=sub(2, bytes(4), critical=True))),
    ("unhashed critical issuer fingerprint",
     _sig(unhashed=sub(33, b"\x04" + bytes.fromhex(CUST[0].fp), critical=True))),
    ("new-format header", bytes([0xC2, len(GOOD) - 2]) + GOOD[2:]),
    # 0xC8 is a NEW-format header (tag 8, compressed data); an old-format reader takes it
    # for tag 2 with a one-octet length, so ignoring bit 6 would read this as a signature
    ("new-format header that an old-format reader takes for tag 2",
     bytes([0xC8, len(GOOD) - 2]) + GOOD[2:]),
    ("partial length", bytes([0xC2, 0xE1]) + GOOD[2:]),
    ("indefinite length", bytes([GOOD[0] | 3]) + GOOD[2:]),
    ("high bit clear", bytes([GOOD[0] & 0x7F]) + GOOD[1:]),
    ("tag 6 in a signature file", pkt(6, CUST[0].body)),
    ("tag 13 in a signature file", pkt(13, b"uid")),
    ("tag 0", pkt(0, b"")),
    ("trailing byte", GOOD + b"\x00"),
    ("trailing junk header", GOOD + b"\x88"),
    ("empty", b""),
    ("packet length past the end", GOOD[:-3]),
    ("packet length lies by one", bytes([GOOD[0], GOOD[1] + 1]) + GOOD[2:]),
    ("zero-length packet", pkt(2, b"")),
    ("one-octet packet", pkt(2, b"\x04")),
    ("hashed area 0xFFFF", GOOD[:6] + b"\xff\xff" + GOOD[8:]),
    ("unhashed area 0xFFFF", pkt(2, GOOD[2:8] + GOOD[8:8 + 29] + b"\xff\xff" + GOOD[8 + 29 + 2:])),
    ("subpacket length zero", _sig(hashed=b"\x00" + sub(33, b"\x04" + bytes.fromhex(CUST[0].fp)))),
    ("subpacket length past the area (1 octet)", _sig(hashed=b"\x7f\x21\x04")),
    ("subpacket length past the area (2 octets)", _sig(hashed=b"\xc1\x00\x21\x04")),
    ("subpacket length past the area (5 octets)", _sig(hashed=b"\xff\xff\xff\xff\xff\x21")),
    ("subpacket length cut short (2 octets)", _sig(hashed=b"\xc1")),
    ("subpacket length cut short (5 octets)", _sig(hashed=b"\xff\x00\x00")),
    ("unhashed subpacket past the area", _sig(unhashed=b"\x7f\x10\x00")),
    ("too many subpackets", _sig(extra_hashed=sub(100, b"") * (_openpgp.MAX_SUBPACKETS + 1))),
    ("no digest prefix", pkt(2, GOOD[2:2 + 6 + 29 + 2 + 10])),
    ("r bit count zero", pkt(2, GOOD[2:-68] + b"\x00\x00" + GOOD[-66:])),
    ("r bit count over 256",
     pkt(2, GOOD[2:-68] + b"\x01\x01" + b"\x01" + b"\x00" * 32 + GOOD[-34:])),
    ("r bit count 0xFFFF", pkt(2, GOOD[2:-68] + b"\xff\xff" + GOOD[-66:])),
    ("r bit count lies", pkt(2, GOOD[2:-68] + b"\x00\xff" + GOOD[-66:])),
    ("r leading zero octet",
     pkt(2, GOOD[2:-68] + b"\x01\x01\x00" + GOOD[-66:-34][:32] + GOOD[-34:])),
    ("s truncated", GOOD[:-10]),
    ("s missing", pkt(2, GOOD[2:-34])),
    ("trailing byte inside the packet", pkt(2, GOOD[2:] + b"\x00")),
])
def test_a_signature_file_outside_the_profile_is_an_open_pgp_error(name: str, data: bytes) -> None:
    raises(OpenPgpError, lambda: _openpgp.read_signatures(data))
    b = bundle()                                  # and through the verifier, after the keys
    raises(OpenPgpError, lambda: replace(b, tnl_sig=data).call())


def test_unknown_non_critical_and_nested_subpackets_are_ignored_not_recursed() -> None:
    embedded = sub(32, GOOD)                                  # a whole signature packet inside
    extras = (sub(100, b"unknown but not critical"), embedded, sub(20, bytes(8)),
              sub(27, b"\x03"), sub(34, b"\x01"))
    b = bundle()
    wrapped = b"".join(sig_packet(k, b.tnl, extra_hashed=b"".join(extras)) for k in CUST[:2])
    assert replace(b, tnl_sig=wrapped).call().version == 4


@pytest.mark.parametrize("name,data,fragment", [
    ("no creation time", _sig(hashed=_signer_hashed()), "without a hashed creation-time"),
    ("two creation times", _sig(extra_hashed=CTIME), "exactly one creation-time"),
    ("creation time of 2 octets", _sig(hashed=_signer_hashed(sub(2, b"\x00\x01"))),
     "exactly one creation-time"),
    ("unhashed critical unknown", _sig(unhashed=sub(100, b"x", critical=True)),
     "critical subpacket (type 100) in the unhashed area"),
    ("unhashed critical issuer key id", _sig(unhashed=sub(16, bytes(8), critical=True)),
     "critical subpacket (type 16) in the unhashed area"),
])
def test_the_creation_time_and_unhashed_rules_name_themselves(
        name: str, data: bytes, fragment: str) -> None:
    """The profile table checks the class; this checks the reason, so a row cannot pass on
    some other, earlier refusal."""
    err = raises(OpenPgpError, lambda: _openpgp.read_signatures(data))
    assert fragment in str(err), str(err)


def test_what_gnupg_accepts_in_those_areas_is_accepted() -> None:
    """GnuPG 2.5.24 accepts each of these (checked with the same bytes), so refusing them
    would be an outage with nothing protected: a critical creation time (the reader
    understands type 2), the creation time before or after the issuer, an empty or a
    non-critical unhashed area."""
    b = bundle()

    def hashed_ct_first(k: Key) -> dict[str, Any]:
        return dict(hashed=sub(2, (1_790_000_100).to_bytes(4, "big"), critical=True)
                    + _signer_hashed(fp=k.fp))

    def hashed_ct_last(k: Key) -> dict[str, Any]:
        return dict(hashed=_signer_hashed(
            sub(2, (1_790_000_100).to_bytes(4, "big"), critical=True), fp=k.fp))

    variants: list[Callable[[Key], dict[str, Any]]] = [
        hashed_ct_first, hashed_ct_last,
        lambda k: dict(unhashed=b""),
        lambda k: dict(unhashed=sub(100, b"x")),
        lambda k: dict(unhashed=sub(16, bytes.fromhex(k.fp)[-8:]) * 3 + sub(20, bytes(8))),
    ]
    for variant in variants:
        sigs = b"".join(sig_packet(k, b.tnl, **variant(k)) for k in CUST[:2])
        assert replace(b, tnl_sig=sigs).call().version == 4


def test_a_subpacket_inside_a_packet_inside_a_packet_is_not_followed() -> None:
    # a signature file that is one valid packet followed by bytes that LOOK like another
    # packet header are trailing bytes: refused, never skipped or recursed into
    raises(OpenPgpError, lambda: _openpgp.read_signatures(GOOD + GOOD[:1]))
    # a self-referential length: the packet claims a body that includes its own header
    raises(OpenPgpError, lambda: _openpgp.read_signatures(bytes([0x88, 0xFF]) + GOOD))


def test_a_packet_flood_stops_at_the_cap_before_any_ecdsa(monkeypatch: pytest.MonkeyPatch) -> None:
    b = bundle()
    tiny = sig_packet(CUST[0], b.tnl, hashed=_signer_hashed(CTIME), unhashed=b"")
    flood = tiny * ((_openpgp.MAX_SIGNATURE_FILE_BYTES // len(tiny)))
    assert len(flood) <= _openpgp.MAX_SIGNATURE_FILE_BYTES
    assert len(flood) // len(tiny) > _openpgp.MAX_PACKETS
    calls: list[str] = []
    real = _openpgp.verify
    monkeypatch.setattr(_openpgp, "verify",
                        lambda sig, doc, key: calls.append(key.fingerprint) or real(sig, doc, key))
    raises(OpenPgpError, lambda: replace(b, tnl_sig=flood).call())
    assert calls == [ANCHOR.fp]                 # only the anchor's check of the key list ran


def test_the_number_of_ecdsa_checks_is_bounded_by_the_packet_cap(
        monkeypatch: pytest.MonkeyPatch) -> None:
    b = bundle()
    tiny = sig_packet(CUST[0], b.tnl, hashed=_signer_hashed(CTIME), unhashed=b"")
    full = tiny * _openpgp.MAX_PACKETS                           # the most the cap allows
    assert len(full) <= _openpgp.MAX_SIGNATURE_FILE_BYTES
    calls: list[str] = []
    real = _openpgp.verify
    monkeypatch.setattr(_openpgp, "verify",
                        lambda sig, doc, key: calls.append(key.fingerprint) or real(sig, doc, key))
    raises(NodeListThresholdError, lambda: replace(b, tnl_sig=full).call())   # one signer of 2
    assert calls.count(CUST[0].fp) == _openpgp.MAX_PACKETS
    assert len(calls) == _openpgp.MAX_PACKETS + 1                  # plus the anchor's check


# ======================================================================================
# key list rollback, floors and the latent replay hole
# ======================================================================================
def _rotation() -> tuple[Bundle, Bundle]:
    """Key list v1 (custodians 0,1; later retired) and v2 (custodians 2,3), and a FRESH node
    list signed by the retired custodians against the old key list."""
    old = bundle(CUST[:2], 2, keys_version=1)
    new = bundle(CUST[2:], 2, keys_version=2, tnl_doc=make_tnl(keysVersion=2))
    return old, new


def test_old_key_list_replay_is_accepted_by_a_stateless_caller_and_stopped_by_the_floor() -> None:
    """The latent hole ADR-0009 describes, named so the floor's job is explicit: retired
    custodians (threshold many of them) sign a fresh node list against an OLD but validly
    signed key list. A caller that passes neither a floor nor a persisted pair accepts it."""
    old, new = _rotation()
    fresh_old = old.with_tnl(encode(make_tnl(version=5)))             # signed by the retired keys
    assert fresh_old.call(list_floor=1, keys_floor=1).version == 5    # accepted: the hole
    raises(NodeListRollback, lambda: fresh_old.call(keys_floor=2))    # the shipped-floor bound
    new_pair = Accepted(2, hashlib.sha256(new.keys).hexdigest())
    raises(NodeListRollback, lambda: fresh_old.call(last_accepted_keys=new_pair))
    assert new.call(keys_floor=2, last_accepted_keys=new_pair).keys_version == 2


def test_the_key_list_floor_is_checked_against_the_key_lists_own_version() -> None:
    """Key list version 2 signing a node list that names keysVersion 1 must pass with
    keys_floor=2: comparing the floor to the node list's keysVersion would raise here."""
    b = bundle(keys_version=2, tnl_doc=make_tnl(keysVersion=1))
    assert b.call(keys_floor=2).keys_version == 1
    raises(NodeListRollback, lambda: b.call(keys_floor=3))


def test_a_node_list_needing_a_newer_key_list_is_a_rollback() -> None:
    b = bundle(keys_version=2, tnl_doc=make_tnl(keysVersion=3))
    err = raises(NodeListRollback, b.call)
    assert "needs key list version 3" in str(err)
    assert bundle(keys_version=2, tnl_doc=make_tnl(keysVersion=2)).call().keys_version == 2


def test_equal_version_with_different_bytes_is_a_rollback_and_the_same_bytes_pass() -> None:
    b = bundle()
    same = Accepted(4, hashlib.sha256(b.tnl).hexdigest())
    assert b.call(last_accepted_list=same).version == 4
    reissued = b.with_tnl(encode(make_tnl(issued="2026-11-02T00:00:00Z")))
    raises(NodeListRollback, lambda: reissued.call(last_accepted_list=same))
    higher = b.with_tnl(encode(make_tnl(version=5)))
    assert higher.call(last_accepted_list=same).version == 5
    lower = b.with_tnl(encode(make_tnl(version=3)))
    raises(NodeListRollback, lambda: lower.call(last_accepted_list=same, list_floor=1))
    raises(NodeListRollback, lambda: lower.call())                    # and the shipped floor


def test_the_two_pairs_are_independent() -> None:
    b = bundle()
    list_pair = Accepted(4, hashlib.sha256(b.tnl).hexdigest())
    keys_pair = Accepted(1, hashlib.sha256(b.keys).hexdigest())
    assert b.call(last_accepted_list=list_pair, last_accepted_keys=keys_pair).version == 4
    # swapped: the key list's digest offered as the list's last bytes (same version 1 vs 4)
    raises(NodeListRollback, lambda: b.call(last_accepted_list=Accepted(4, keys_pair.sha256)))
    raises(NodeListRollback, lambda: b.call(last_accepted_keys=Accepted(1, list_pair.sha256)))


# ======================================================================================
# the node list: schema, origins, time
# ======================================================================================
def _mutated(mutate: Callable[[dict[str, Any]], None]) -> Bundle:
    doc = make_tnl()
    mutate(doc)
    return bundle(tnl_doc=doc)


def _set_org(value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc["environments"]["prod"][0]["organisation"] = value
    return mutate


def _set_node(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc["environments"]["prod"][0][field] = value
    return mutate


def _set_top(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc[field] = value
    return mutate


def _drop_top(field: str) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        del doc[field]
    return mutate


def _drop_node(field: str) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        del doc["environments"]["prod"][0][field]
    return mutate


def _env(value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc["environments"] = value
    return mutate


def _add_env(name: str) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc["environments"][name] = nodes_for("prod", 1)
    return mutate


def _rename_env(old: str, new: str) -> Callable[[dict[str, Any]], None]:
    """*old*'s nodes under the name *new*: the count of members is unchanged."""
    def mutate(doc: dict[str, Any]) -> None:
        doc["environments"][new] = doc["environments"].pop(old)
    return mutate


def _only_env(name: str) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc["environments"] = {name: nodes_for("prod", 1)}
    return mutate


def _add_node_member(doc: dict[str, Any]) -> None:
    doc["environments"]["prod"][0]["extra"] = "x"


def _empty_env(doc: dict[str, Any]) -> None:
    doc["environments"]["prod"] = []


def _duplicate_in_env(doc: dict[str, Any]) -> None:
    doc["environments"]["prod"][1]["url"] = doc["environments"]["prod"][0]["url"]


def _as_obj(doc: dict[str, Any]) -> None:
    doc["environments"]["prod"] = {"0": doc["environments"]["prod"][0]}


def _string_node(doc: dict[str, Any]) -> None:
    doc["environments"]["prod"][0] = doc["environments"]["prod"][0]["url"]


def _too_many_nodes(doc: dict[str, Any]) -> None:
    doc["environments"]["prod"] = [
        {"url": f"https://api.ebsi.n{i}.example.org", "country": "BE", "organisation": "O"}
        for i in range(nodes_mod.MAX_NODES + 1)]


def _issued_expires_doc(issued: str, expires: str) -> Callable[[dict[str, Any]], None]:
    def mutate(doc: dict[str, Any]) -> None:
        doc["issued"], doc["expires"] = issued, expires
    return mutate


def _digits(script: str) -> str:
    """'2026' written in the decimal digits of *script* (Python's \\d would accept them)."""
    return "".join(unicodedata.lookup(f"{script} DIGIT {w}") for w in ("TWO", "ZERO", "TWO", "SIX"))


URL = "https://api.ebsi.good.example.org"
TS = "2026-11-01T00:00:00Z"
SCHEMA_NEGATIVES: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
    ("missing version", _drop_top("version")), ("missing keysVersion", _drop_top("keysVersion")),
    ("missing issued", _drop_top("issued")), ("missing expires", _drop_top("expires")),
    ("missing environments", _drop_top("environments")),
    ("extra top-level key", _set_top("extra", 1)),
    ("version true", _set_top("version", True)), ("version 4.0", _set_top("version", 4.0)),
    ("version string", _set_top("version", "4")), ("version 0", _set_top("version", 0)),
    ("version -1", _set_top("version", -1)), ("version null", _set_top("version", None)),
    ("version 2**63", _set_top("version", 2 ** 63)),
    ("keysVersion true", _set_top("keysVersion", True)),
    ("keysVersion 1.0", _set_top("keysVersion", 1.0)),
    ("keysVersion 0", _set_top("keysVersion", 0)),
    ("issued no Z", _set_top("issued", "2026-11-01T00:00:00")),
    ("issued offset", _set_top("issued", "2026-11-01T00:00:00+00:00")),
    ("issued fraction", _set_top("issued", "2026-11-01T00:00:00.5Z")),
    ("issued lowercase z", _set_top("issued", "2026-11-01T00:00:00z")),
    ("issued month 13", _set_top("issued", "2026-13-01T00:00:00Z")),
    ("issued 30 February", _set_top("issued", "2026-02-30T00:00:00Z")),
    ("issued hour 24", _set_top("issued", "2026-11-01T24:00:00Z")),
    ("issued second 60", _set_top("issued", "2026-11-01T00:00:60Z")),
    ("issued year 0000", _set_top("issued", "0000-11-01T00:00:00Z")),
    ("issued trailing newline", _set_top("issued", TS + "\n")),
    ("issued leading space", _set_top("issued", " " + TS)),
    ("issued arabic-indic digits",
     _set_top("issued", _digits("ARABIC-INDIC") + "-11-01T00:00:00Z")),
    ("issued fullwidth digits", _set_top("issued", _digits("FULLWIDTH") + "-11-01T00:00:00Z")),
    ("issued number", _set_top("issued", 1793491200)),
    ("expires no Z", _set_top("expires", "2026-12-01T00:00:00")),
    ("expires trailing newline", _set_top("expires", "2026-12-01T00:00:00Z\n")),
    ("expires equals issued", _set_top("expires", TS)),
    ("expires before issued", _set_top("expires", "2026-10-31T00:00:00Z")),
    ("expires 90 days + 1 s", _issued_expires_doc("2026-11-01T00:00:00Z", "2027-01-30T00:00:01Z")),
    ("environments null", _env(None)), ("environments list", _env([])),
    ("environments empty", _env({})), ("environments with an extra name", _add_env("test")),
    ("environments named production", _add_env("production")),
    # inside the 1-to-3 bound, so only the check of the names themselves can refuse them
    ("environments with a third name bogus", _rename_env("preprod", "bogus")),
    ("environments with pilot renamed legacy", _rename_env("pilot", "legacy")),
    ("environments with prod renamed Prod", _rename_env("prod", "Prod")),
    ("environments of one unknown name", _only_env("bogus")),
    ("environments named Prod", _add_env("Prod")),
    ("empty environment list", _empty_env), ("environment as object", _as_obj),
    ("node as string", _string_node), ("node extra member", _add_node_member),
    ("node missing url", _drop_node("url")), ("node missing country", _drop_node("country")),
    ("node missing organisation", _drop_node("organisation")),
    ("url path", _set_node("url", URL + "/v1")), ("url port", _set_node("url", URL + ":443")),
    ("url query", _set_node("url", URL + "?a=1")), ("url fragment", _set_node("url", URL + "#a")),
    ("url credentials", _set_node("url", "https://u:p@api.ebsi.good.example.org")),
    ("url upper case", _set_node("url", "https://api.ebsi.GOOD.example.org")),
    ("url trailing newline", _set_node("url", URL + "\n")),
    ("url trailing dot", _set_node("url", URL + ".")),
    ("url empty label", _set_node("url", "https://api.ebsi..example.org")),
    ("url U-label",
     _set_node("url", "https://api.ebsi.b\N{LATIN SMALL LETTER U WITH DIAERESIS}cher.example.org")),
    ("url http", _set_node("url", "http://api.ebsi.good.example.org")),
    ("url wrong env prefix", _set_node("url", "https://api-pilot.ebsi.good.example.org")),
    ("url only the prefix", _set_node("url", "https://api.ebsi.")),
    ("url bare prefix without dot", _set_node("url", "https://api.ebsi")),
    ("url hyphen-leading label", _set_node("url", "https://api.ebsi.-bad.example.org")),
    ("url hyphen-trailing label", _set_node("url", "https://api.ebsi.bad-.example.org")),
    ("url label of 64", _set_node("url", "https://api.ebsi." + "a" * 64 + ".org")),
    ("url over 253", _set_node("url", "https://api.ebsi." + ".".join(["a" * 60] * 4) + ".org")),
    ("url empty", _set_node("url", "")), ("url null", _set_node("url", None)),
    ("url number", _set_node("url", 5)),
    ("url space", _set_node("url", "https://api.ebsi.a b.org")),
    ("url underscore", _set_node("url", "https://api.ebsi.a_b.org")),
    ("duplicate url in an environment", _duplicate_in_env),
    ("country lower case", _set_node("country", "be")),
    ("country three letters", _set_node("country", "BEL")),
    ("country trailing newline", _set_node("country", "BE\n")),
    ("country one letter", _set_node("country", "B")),
    ("country digits", _set_node("country", "12")), ("country empty", _set_node("country", "")),
    ("country non-ASCII", _set_node("country", "B\N{LATIN CAPITAL LETTER E WITH ACUTE}")),
    ("country null", _set_node("country", None)),
    ("organisation empty", _set_org("")), ("organisation 201 characters", _set_org("a" * 201)),
    ("organisation leading space", _set_org(" a")), ("organisation trailing space", _set_org("a ")),
    ("organisation leading tab", _set_org("\ta")),
    ("organisation trailing newline", _set_org("a\n")),
    ("organisation no-break space", _set_org("a\N{NO-BREAK SPACE}")),
    ("organisation leading no-break space", _set_org("\N{NO-BREAK SPACE}a")),
    ("organisation ideographic space", _set_org("a\N{IDEOGRAPHIC SPACE}")),
    ("organisation zero-width no-break space", _set_org("\N{ZERO WIDTH NO-BREAK SPACE}a")),
    ("organisation interior newline", _set_org("a\nb")),
    ("organisation interior carriage return", _set_org("a\rb")),
    ("organisation interior line separator", _set_org("a\N{LINE SEPARATOR}b")),
    ("organisation only a space", _set_org(" ")),
    ("organisation lone high surrogate", _set_org("a\ud800b")),
    ("organisation lone low surrogate", _set_org("\udfff")),
    ("organisation number", _set_org(5)), ("organisation null", _set_org(None)),
    ("too many nodes", _too_many_nodes),
]


_BLAMED = {"version": "tnl.json version", "keysVersion": "keysVersion", "issued": "issued",
           "expires": "expires", "country": ".country", "organisation": ".organisation",
           "url": ".url", "duplicate": "listed twice", "node": "environments.prod[0]",
           "missing": "exactly the members", "extra": "exactly the members",
           "environments": "environments", "environment": "environments",
           "empty": "environments.prod", "too": "more than"}


@pytest.mark.parametrize("name,mutate", SCHEMA_NEGATIVES, ids=[n for n, _ in SCHEMA_NEGATIVES])
def test_schema_negatives_are_malformed(
        name: str, mutate: Callable[[dict[str, Any]], None]) -> None:
    doc = make_tnl()
    mutate(doc)
    err = raises(NodeListMalformed, bundle(tnl_doc=doc).call)
    # the right field is blamed, not some unrelated earlier failure
    fragment = _BLAMED.get(name.split()[0])
    if fragment is not None:
        assert fragment in str(err), str(err)


def test_the_boundary_values_that_pass() -> None:
    ok = [
        _set_top("expires", "2027-01-30T00:00:00Z"),              # exactly 90 days
        _set_org("a"), _set_org("a" * 200), _set_org("a b\tc"), _set_org("a\N{ZERO WIDTH SPACE}b"),
        _set_org("\N{LATIN SMALL LETTER E WITH ACUTE}" * 200), _set_org("\U0001F600"),
        _set_org("a\N{MIDDLE DOT}"),
        _set_node("url", "https://api.ebsi." + "a" * 63 + ".org"),
        _set_node("url", "https://api.ebsi.xn--bcher-kva.example.org"),
        _set_node("url", "https://api.ebsi.a-b.c-d.org"), _set_node("country", "ZZ"),
        _set_top("version", 2 ** 63 - 1),
    ]
    for mutate in ok:
        doc = make_tnl()
        mutate(doc)
        b = bundle(tnl_doc=doc)
        assert b.call(list_floor=1).environment == "prod"


def test_every_environment_prefix_is_enforced_per_environment() -> None:
    for env, other in (("pilot", "prod"), ("preprod", "pilot"), ("prod", "preprod")):
        doc = make_tnl()
        doc["environments"][env][0]["url"] = f"{PREFIX[other]}x.example.org"
        raises(NodeListMalformed, bundle(tnl_doc=doc).call)
    # a node of one environment cannot also be listed in another: the prefixes differ
    doc = make_tnl()
    doc["environments"]["prod"][0]["url"] = doc["environments"]["pilot"][0]["url"]
    raises(NodeListMalformed, bundle(tnl_doc=doc).call)


def test_the_whole_document_is_validated_even_for_one_environment() -> None:
    doc = make_tnl()
    doc["environments"]["pilot"][0]["country"] = "xx"              # broken, in the unwanted env
    raises(NodeListMalformed, lambda: bundle(tnl_doc=doc).call(environment="prod"))


def test_a_missing_environment_is_its_own_error() -> None:
    doc = make_tnl()
    del doc["environments"]["preprod"]
    del doc["environments"]["pilot"]
    b = bundle(tnl_doc=doc)
    assert b.call(environment="prod").environment == "prod"
    raises(NodeListEnvironmentMissing, lambda: b.call(environment="pilot"))
    raises(NodeListEnvironmentMissing, lambda: b.call(environment="preprod"))
    for bad in ("production", "conformance", "", "Prod"):
        raises(NodeListConfigError, lambda: b.call(environment=bad))


RAW_NEGATIVES: list[tuple[str, bytes]] = [
    ("BOM", b"\xef\xbb\xbf" + encode(make_tnl())),
    ("NaN", encode(make_tnl()).replace(b'"version": 4', b'"version": NaN')),
    ("Infinity", encode(make_tnl()).replace(b'"version": 4', b'"version": Infinity')),
    ("-Infinity", encode(make_tnl()).replace(b'"version": 4', b'"version": -Infinity')),
    ("duplicate top-level member", b'{"version": 4, "version": 5}'),
    ("duplicate node member", encode(make_tnl()).replace(
        b'"country": "BE",', b'"country": "BE", "country": "NL",', 1)),
    ("duplicate environment",
     encode(make_tnl()).replace(b'"prod": [', b'"pilot": [], "prod": [', 1)),
    ("invalid UTF-8", encode(make_tnl()).replace(b"Org 0", b"Org \xff", 1)),
    ("overlong UTF-8", encode(make_tnl()).replace(b"Org 0", b"Org \xc0\xaf", 1)),
    ("UTF-16", encode(make_tnl()).decode().encode("utf-16")),
    ("top-level array", b"[]"), ("top-level string", b'"x"'), ("top-level null", b"null"),
    ("top-level number", b"4"), ("empty", b""), ("whitespace", b" \n"),
    ("truncated", encode(make_tnl())[:-10]), ("trailing comma", b'{"version": 4,}'),
    ("trailing garbage", encode(make_tnl()) + b"x"), ("two documents", encode(make_tnl()) * 2),
    ("single quotes", b"{'version': 4}"), ("comments", b'{"version": 4 /* x */}'),
    ("nested past the bound", b'{"environments": ' + b"[" * 150 + b"]" * 150 + b"}"),
    ("nested past the interpreter", b"[" * 120000 + b"]" * 120000),
    ("huge integer", b'{"version": ' + b"9" * 6000 + b"}"),
    ("control character in a string", encode(make_tnl()).replace(b"Org 0", b"Org\x010", 1)),
    ("raw newline in a string", encode(make_tnl()).replace(b"Org 0", b"Org\n0", 1)),
]


@pytest.mark.parametrize("name,raw", RAW_NEGATIVES, ids=[n for n, _ in RAW_NEGATIVES])
def test_hostile_json_text_is_malformed(name: str, raw: bytes) -> None:
    raises(NodeListMalformed, bundle().with_tnl(raw).call)


@pytest.mark.parametrize("name,raw", [
    ("BOM", b"\xef\xbb\xbf" + encode(make_keys(CUST[:2], 2))),
    ("NaN threshold",
     encode(make_keys(CUST[:2], 2)).replace(b'"threshold": 2', b'"threshold": NaN')),
    ("duplicate member", b'{"version": 1, "version": 2, "threshold": 1, "keys": []}'),
    ("array", b"[]"), ("invalid UTF-8", b"\xff\xfe"),
    ("extra member", encode({**make_keys(CUST[:2], 2), "extra": 1})),
    ("missing threshold",
     encode({k: v for k, v in make_keys(CUST[:2], 2).items() if k != "threshold"})),
    ("version 0", encode(make_keys(CUST[:2], 2, version=0))),
    ("version true", encode({**make_keys(CUST[:2], 2), "version": True})),
    ("keys empty", encode({**make_keys(CUST[:2], 1), "keys": []})),
    ("keys not a list", encode({**make_keys(CUST[:2], 1), "keys": {}})),
    ("too many custodians", encode(make_keys(
        [Key(1_790_001_000 + i) for i in range(nodes_mod.MAX_CUSTODIANS + 1)], 2))),
    ("custodian not an object", encode({**make_keys(CUST[:2], 2), "keys": ["x", "y"]})),
    ("custodian extra member", encode({**make_keys(CUST[:2], 2), "keys": [
        {**e, "extra": 1} for e in make_keys(CUST[:2], 2)["keys"]]})),
    ("custodian missing publicKey", encode({**make_keys(CUST[:2], 2), "keys": [
        {"fingerprint": CUST[0].fp}, {"fingerprint": CUST[1].fp}]})),
    ("fingerprint lower case", encode({**make_keys(CUST[:2], 2), "keys": [
        {**e, "fingerprint": e["fingerprint"].lower()} for e in make_keys(CUST[:2], 2)["keys"]]})),
    ("fingerprint with newline", encode({**make_keys(CUST[:2], 2), "keys": [
        {**e, "fingerprint": e["fingerprint"] + "\n"} for e in make_keys(CUST[:2], 2)["keys"]]})),
    ("fingerprint short", encode({**make_keys(CUST[:2], 2), "keys": [
        {**e, "fingerprint": e["fingerprint"][:-2]} for e in make_keys(CUST[:2], 2)["keys"]]})),
], ids=lambda v: v if isinstance(v, str) else "")
def test_a_hostile_but_authentic_key_list_is_malformed(name: str, raw: bytes) -> None:
    raises(NodeListMalformed, bundle().with_keys(raw).call)


# ---- time -----------------------------------------------------------------------------
def _issued_expires(issued: str, expires: str) -> Bundle:
    return bundle(tnl_doc=make_tnl(issued=issued, expires=expires))


def test_exactly_90_days_passes_and_one_second_more_does_not() -> None:
    assert _issued_expires("2026-11-01T00:00:00Z", "2026-11-30T00:00:00Z").call()
    ninety = _issued_expires("2026-11-01T00:00:00Z", "2027-01-30T00:00:00Z")
    assert ninety.call(now=datetime(2026, 12, 1, tzinfo=timezone.utc)).expires.year == 2027
    raises(NodeListMalformed, _issued_expires("2026-11-01T00:00:00Z", "2027-01-30T00:00:01Z").call)


def test_time_rules_on_a_synthetic_list() -> None:
    b = bundle()
    issued = datetime(2026, 11, 1, tzinfo=timezone.utc)
    expires = datetime(2026, 12, 1, tzinfo=timezone.utc)
    raises(NodeListExpired, lambda: b.call(now=expires))
    assert b.call(now=expires - timedelta(seconds=1))
    assert b.call(now=issued - timedelta(seconds=300))
    raises(NodeListNotYetValid, lambda: b.call(now=issued - timedelta(seconds=301)))
    age = SYN_NOW - issued
    assert b.call(max_age=age)
    raises(NodeListStale, lambda: b.call(max_age=age - timedelta(seconds=1)))


def test_extreme_clock_values_never_overflow() -> None:
    b = bundle()
    raises(NodeListExpired, lambda: b.call(now=datetime.max.replace(tzinfo=timezone.utc)))
    raises(NodeListNotYetValid, lambda: b.call(now=datetime.min.replace(tzinfo=timezone.utc)))
    far = bundle(tnl_doc=make_tnl(issued="9999-12-31T00:00:00Z", expires="9999-12-31T23:59:59Z"))
    raises(NodeListNotYetValid, far.call)
    huge = timedelta.max
    assert b.call(max_age=huge)
    year_1 = bundle(tnl_doc=make_tnl(issued="0001-01-01T00:00:00Z", expires="0001-01-02T00:00:00Z"))
    raises(NodeListExpired, year_1.call)


# ======================================================================================
# the bounded loader
# ======================================================================================
def test_reject_ambiguous_is_off_by_default_and_exact_when_on() -> None:
    assert _json.loads('{"a": 1, "a": 2}') == {"a": 2}
    assert _json.loads("[NaN]")[0] != _json.loads("[NaN]")[0]            # nan, as before
    for text in ('{"a": 1, "a": 2}', '{"x": {"a": 1, "a": 2}}', '[{"a": 1, "a": 2}]',
                 "[NaN]", "[Infinity]", "[-Infinity]", '{"a": NaN}'):
        with pytest.raises(ValueError):
            _json.loads(text, reject_ambiguous=True)
    assert _json.loads('{"a": 1, "b": {"a": 2}}', reject_ambiguous=True) == {"a": 1, "b": {"a": 2}}
    with pytest.raises(ValueError, match="nested"):
        _json.loads("[" * 150 + "]" * 150, reject_ambiguous=True)


# ======================================================================================
# fuzzing: success, or a typed error; never a bare exception, never a different answer
# ======================================================================================
FUZZ = settings(
    max_examples=250, deadline=None, database=None, derandomize=True,
    suppress_health_check=[HealthCheck.too_slow])
REAL_TNL, REAL_TNL_SIG = (FIX / "tnl.json").read_bytes(), (FIX / "tnl.json.sig").read_bytes()
REAL_KEYS = (FIX / "trusted-keys.json").read_bytes()
REAL_KEYS_SIG = (FIX / "trusted-keys.json.sig").read_bytes()
REAL_BLOCKS = [e["publicKey"] for e in json.loads(REAL_KEYS)["keys"]] + [
    (FIX / "keylist-key.asc").read_text("ascii")]
NOW_REAL = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def _real(**over: Any) -> Any:
    args: dict[str, Any] = dict(
        tnl=REAL_TNL, tnl_sig=REAL_TNL_SIG, keys=REAL_KEYS, keys_sig=REAL_KEYS_SIG,
        environment="prod", now=NOW_REAL, last_accepted_list=None, last_accepted_keys=None)
    args.update(over)
    return verify_node_list(**args)


@functools.cache
def _baseline() -> Any:
    """The real chain's result, computed on first use: a verifier regression must show up
    as named test failures, not as a collection error of this whole module."""
    return _real()


_ops = st.lists(st.tuples(st.sampled_from(["flip", "insert", "delete", "truncate"]),
                          st.integers(min_value=0, max_value=10 ** 6),
                          st.integers(min_value=0, max_value=255)), min_size=1, max_size=4)


def apply_ops(data: bytes, ops: list[tuple[str, int, int]]) -> bytes:
    out = bytearray(data)
    for op, index, value in ops:
        if not out:
            break
        i = index % len(out)
        if op == "flip":
            out[i] ^= 1 << (value % 8)
        elif op == "insert":
            out.insert(i, value)
        elif op == "delete":
            del out[i]
        else:
            del out[i:]
    return bytes(out)


@FUZZ
@given(st.binary(max_size=400))
def test_fuzz_signature_reader_on_arbitrary_bytes(data: bytes) -> None:
    try:
        _openpgp.read_signatures(data)
    except OpenPgpError:
        pass


@FUZZ
@given(st.text(max_size=300) | st.binary(max_size=300).map(lambda b: b.decode("latin-1")))
def test_fuzz_dearmor_and_key_block_reader_on_arbitrary_text(text: str) -> None:
    for fn in (_openpgp.dearmor, _openpgp.read_public_key_block):
        try:
            fn(text)
        except OpenPgpError:
            pass


@FUZZ
@given(st.binary(max_size=200), st.integers(0, 200), st.integers(0, 70000))
def test_fuzz_the_low_level_readers(data: bytes, pos: int, bits: int) -> None:
    for fn in (lambda: _openpgp._packets(data), lambda: _openpgp._subpackets(data),
               lambda: _openpgp._mpi(data, pos, bits)):
        try:
            fn()
        except OpenPgpError:
            pass


@FUZZ
@given(st.binary(max_size=300), st.binary(max_size=300), st.binary(max_size=200),
       st.binary(max_size=200))
def test_fuzz_the_verifier_on_arbitrary_bytes(a: bytes, b: bytes, c: bytes, d: bytes) -> None:
    try:
        _real(tnl=a, tnl_sig=b, keys=c, keys_sig=d)
    except NodeListError:
        pass


@FUZZ
@given(_ops)
def test_fuzz_mutated_signature_files_give_the_same_answer_or_a_typed_error(
        ops: list[tuple[str, int, int]]) -> None:
    for name in ("tnl_sig", "keys_sig"):
        original = REAL_TNL_SIG if name == "tnl_sig" else REAL_KEYS_SIG
        mutated = apply_ops(original, ops)
        try:
            result = _real(**{name: mutated})
        except NodeListError:
            continue
        assert result == _baseline()   # an accepted mutation (the unhashed area) changes nothing


@FUZZ
@given(_ops, st.sampled_from([0, 1, 2]))
def test_fuzz_mutated_key_blocks_give_the_same_key_or_a_typed_error(
        ops: list[tuple[str, int, int]], which: int) -> None:
    armored = REAL_BLOCKS[which]
    baseline = _openpgp.read_public_key_block(armored)
    binary = _openpgp.dearmor(armored)
    for candidate in (armor(apply_ops(binary, ops)),
                      apply_ops(armored.encode(), ops).decode("latin-1")):
        try:
            key = _openpgp.read_public_key_block(candidate)
        except OpenPgpError:
            continue
        # a mutation inside the primary key packet is a DIFFERENT key under a different
        # fingerprint; what must never happen is the same fingerprint over different material
        assert key == baseline or key.fingerprint != baseline.fingerprint


@pytest.mark.parametrize("which", [0, 1, 2])
def test_every_prefix_of_a_key_block_and_a_signature_file_is_typed(which: int) -> None:
    binary = _openpgp.dearmor(REAL_BLOCKS[which])
    baseline = _openpgp.read_public_key_block(REAL_BLOCKS[which])
    for n in range(len(binary) + 1):
        try:
            key = _openpgp.read_public_key_block(armor(binary[:n]))
            assert key == baseline
        except OpenPgpError:
            pass
    for data in (REAL_TNL_SIG, REAL_KEYS_SIG):
        for n in range(len(data) + 1):
            try:
                _openpgp.read_signatures(data[:n])
            except OpenPgpError:
                pass


@pytest.mark.parametrize("kind,length", [
    (0, 0), (0, 1), (0, 255), (1, 0), (1, 1), (1, 65535), (2, 0), (2, 1), (2, 2 ** 32 - 1),
    (2, 2 ** 31), (3, 0), (3, 255)])
def test_old_format_length_types_with_every_kind_of_length(kind: int, length: int) -> None:
    head = bytes([0x80 | 2 << 2 | kind])
    width = (1, 2, 4, 0)[kind]
    data = head + length.to_bytes(width, "big") + b"\x04" * 8 if width else head + b"\x04" * 8
    raises(OpenPgpError, lambda: _openpgp.read_signatures(data))


@FUZZ
@given(st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=20),
    lambda kids: (st.lists(kids, max_size=4)
                  | st.dictionaries(st.text(max_size=12), kids, max_size=5)),
    max_leaves=12))
def test_fuzz_the_schema_validators_on_generated_json(value: Any) -> None:
    for parse in (nodes_mod._parse_list, nodes_mod._parse_key_list):
        try:
            parse(json.dumps(value).encode())
        except NodeListMalformed:
            pass


_PATHS = [("version",), ("keysVersion",), ("issued",), ("expires",), ("environments",),
          ("environments", "prod"), ("environments", "pilot"), ("environments", "prod", 0),
          ("environments", "prod", 0, "url"), ("environments", "prod", 0, "country"),
          ("environments", "prod", 0, "organisation")]
_leaf = (st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=30)
         | st.just([]) | st.just({}) | st.just("https://api.ebsi.x.org")
         | st.just("2026-11-01T00:00:00Z"))


def _set_path(doc: Any, path: tuple[Any, ...], value: Any) -> None:
    for step in path[:-1]:
        doc = doc[step]
    doc[path[-1]] = value


@FUZZ
@given(st.sampled_from(_PATHS), _leaf)
def test_fuzz_near_valid_node_lists_are_accepted_well_formed_or_typed(
        path: tuple[Any, ...], value: Any) -> None:
    doc = copy.deepcopy(make_tnl())
    _set_path(doc, path, value)
    try:
        parsed = nodes_mod._parse_list(json.dumps(doc).encode())
    except NodeListMalformed:
        return
    # an accepted document honours every rule the validator exists to enforce
    assert parsed.version >= 1 and parsed.keys_version >= 1
    assert parsed.issued < parsed.expires <= parsed.issued + timedelta(days=90)
    for env, nodes in parsed.environments.items():
        assert nodes
        for node in nodes:
            assert node.origin.startswith(PREFIX[env]) and node.origin == f"https://{node.host}"
            assert node.host == node.host.lower().strip() and node.host.isascii()
            assert len(node.country) == 2 and 1 <= len(node.organisation) <= 200
