"""
tests/test_ebsi_tnl_golden.py — the Trusted Nodes List verifier against the REAL chain
(issue #319, ADR-0009 D2/D3).

The five artifacts under tests/fixtures/ebsi/tnl/ were recorded byte-for-byte from
https://tnl.ebsi.eu on 2026-10-16 (see the README there). They are the drift alarm: the
reader and the verifier must accept exactly what Europeum signed and reject every
variation of it. Everything that needs a DIFFERENT signed document (rollback after a
rotation, thresholds other than 2-of-2, hostile key blocks) is in
test_ebsi_tnl_synthetic.py, whose in-memory OpenPGP writer is deliberately not shared.

Every test pins ``now`` inside the list's window (issued 2026-10-06T13:33:18Z, expires
2027-01-04T13:33:18Z) or injects its own: nothing reads the wall clock, so this suite does
not go red when the recorded list expires.
"""
from __future__ import annotations

import hashlib
import importlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from openvc import _json
from openvc.errors import OpenvcError
from openvc_ebsi import _openpgp
from openvc_ebsi import nodes as nodes_mod
from openvc_ebsi.errors import (
    EbsiError,
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
from openvc_ebsi.nodes import (
    EUROPEUM_KEY_LIST_ANCHOR,
    KEYS_VERSION_FLOOR,
    LIST_VERSION_FLOOR,
    Accepted,
    Anchor,
    verify_node_list,
)

FIX = Path(__file__).parent / "fixtures" / "ebsi" / "tnl"

ISSUED = datetime(2026, 10, 6, 13, 33, 18, tzinfo=timezone.utc)
EXPIRES = datetime(2027, 1, 4, 13, 33, 18, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
SECOND = timedelta(seconds=1)

SHA256 = {
    "tnl.json": "ebff3ba5b210806d1bd0b302222d81e383312b3cdf068525a143d7a2a7d2fcb1",
    "tnl.json.sig": "1d0438b2c82493786cd026a74db9b6b8f7d6c300b124cab00781ef639c1f7ff5",
    "trusted-keys.json": "2e0f5f1bca81acebb602786137021f86a6a41fa4d6bfa40686c7dc37211f22ea",
    "trusted-keys.json.sig": "db1200d9f8d2cfeb8a47e9960245be3457d47c9ae94de850b61926cc2e2ceff0",
    "keylist-key.asc": "a222771cb519abd48df677519caa7c3614219b9a15885c6ca232ad05f65908e5",
    "tnl.v3.json": "62dc15d78416c15093f64314e99a841e00dac3e7e1c5f12e414e794e84e33b60",
    "tnl.v3.json.sig": "d130f29387bb55c4a57a73e17ea532b8f0867127043c5c52c2bdef423d436105",
}


def _read(name: str) -> bytes:
    return (FIX / name).read_bytes()


TNL, TNL_SIG = _read("tnl.json"), _read("tnl.json.sig")
KEYS, KEYS_SIG = _read("trusted-keys.json"), _read("trusted-keys.json.sig")
ASC = _read("keylist-key.asc")
FIRST_SIG_PACKET = 2 + TNL_SIG[1]            # old format, 1-octet length: 117 + 2 bytes


def _verify(**over: Any):
    args: dict[str, Any] = dict(
        tnl=TNL, tnl_sig=TNL_SIG, keys=KEYS, keys_sig=KEYS_SIG, environment="prod",
        now=NOW, last_accepted_list=None, last_accepted_keys=None)
    args.update(over)
    return verify_node_list(**args)


def _flip(data: bytes, index: int, bit: int = 0) -> bytes:
    out = bytearray(data)
    out[index] ^= 1 << bit
    return bytes(out)


def _locate(sig_file: bytes, n: int) -> dict[str, int]:
    """Byte offsets inside the n-th signature packet of a recorded .sig file (old-format
    headers with a 1-octet length, which is all the recorded files use)."""
    pos = 0
    for _ in range(n):
        pos += 2 + sig_file[pos + 1]
    body = pos + 2
    hashed_len = int.from_bytes(sig_file[body + 4:body + 6], "big")
    hashed = body + 6
    unhashed = hashed + hashed_len + 2
    prefix = unhashed + int.from_bytes(sig_file[hashed + hashed_len:unhashed], "big")
    r_bits = int.from_bytes(sig_file[prefix + 2:prefix + 4], "big")
    r_data = prefix + 4
    s_at = r_data + (r_bits + 7) // 8
    return {"packet": pos, "hashed": hashed, "hashed_len": hashed_len, "prefix": prefix,
            "r": r_data, "s": s_at + 2, "end": body + sig_file[pos + 1]}


# --------------------------------------------------------------------------------------
# the recorded chain verifies, and says what the README says it does
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(SHA256))
def test_fixture_bytes_are_the_recorded_bytes(name: str) -> None:
    assert hashlib.sha256(_read(name)).hexdigest() == SHA256[name]


def test_real_chain_verifies_for_all_three_environments() -> None:
    counts = {}
    host_sets = {}
    for env, expected in (("pilot", 23), ("preprod", 12), ("prod", 10)):
        result = _verify(environment=env)
        assert result.environment == env
        assert (result.version, result.keys_version) == (4, 1)
        assert result.issued == ISSUED and result.expires == EXPIRES
        assert result.issued.utcoffset() == timedelta(0)
        assert len(result.nodes) == expected
        assert len(result.hosts) == expected              # no duplicate host inside
        assert all(n.origin == f"https://{n.host}" for n in result.nodes)
        assert result.accepted_list == Accepted(4, SHA256["tnl.json"])
        assert result.accepted_keys == Accepted(1, SHA256["trusted-keys.json"])
        counts[env] = len(result.nodes)
        host_sets[env] = result.hosts
    assert sum(counts.values()) == 45
    assert not (host_sets["pilot"] & host_sets["preprod"])
    assert not (host_sets["pilot"] & host_sets["prod"])
    assert not (host_sets["preprod"] & host_sets["prod"])
    # none of the 45 hosts is under ebsi.eu (ADR-0009 Option E: a suffix rule fails)
    assert not any(h.endswith(".ebsi.eu") for hs in host_sets.values() for h in hs)


def test_node_fields_come_from_the_list_in_list_order() -> None:
    result = _verify(environment="pilot")
    first = result.nodes[0]
    assert (first.origin, first.country) == ("https://api-pilot.ebsi.grnet.gr", "GR")
    assert first.organisation == "Ministry of Digital Governance / GRNET"
    assert result.hosts == frozenset(n.host for n in result.nodes)
    assert isinstance(result.nodes, tuple)


def test_result_is_equal_for_equal_inputs_and_immutable() -> None:
    a, b = _verify(), _verify()
    assert a == b and hash(a) == hash(b)
    with pytest.raises(AttributeError):
        a.version = 9                                       # type: ignore[misc]
    with pytest.raises(AttributeError):
        a.nodes[0].host = "x"                               # type: ignore[misc]


def test_anchor_equals_the_recorded_key_list_key() -> None:
    key = _openpgp.read_public_key_block(ASC.decode("ascii"))
    assert key.fingerprint == "ACCC82E5FC8902F114929481747CB65CFB7574F9"
    assert (EUROPEUM_KEY_LIST_ANCHOR.fingerprint, EUROPEUM_KEY_LIST_ANCHOR.curve,
            EUROPEUM_KEY_LIST_ANCHOR.public_point) == (key.fingerprint, key.curve, key.point)
    assert Anchor.from_public_key_block(ASC) == EUROPEUM_KEY_LIST_ANCHOR
    assert Anchor.from_public_key_block(ASC.decode("ascii")) == EUROPEUM_KEY_LIST_ANCHOR


def test_custodian_fingerprints_recomputed_from_the_blocks_equal_the_listed_ones() -> None:
    listed = _json.loads(KEYS)
    assert listed["threshold"] == 2 and listed["version"] == 1 and len(listed["keys"]) == 2
    for entry in listed["keys"]:
        key = _openpgp.read_public_key_block(entry["publicKey"])
        assert key.fingerprint == entry["fingerprint"]
        assert key.curve == "P-256" and len(key.point) == 65


def test_the_shipped_floors_do_not_exceed_what_ebsi_published() -> None:
    # a floor can only reject: a careless bump past the recorded versions must fail here,
    # not ship as an outage
    assert LIST_VERSION_FLOOR <= 4
    assert KEYS_VERSION_FLOOR <= 1
    assert _verify() is not None      # and the defaults accept the recorded chain


def test_the_real_signatures_include_high_s_values() -> None:
    # OpenPGP has no low-s rule; two of the three recorded signatures have s above n/2,
    # so a "canonical s" check would reject real signatures
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    sigs = _openpgp.read_signatures(TNL_SIG) + _openpgp.read_signatures(KEYS_SIG)
    assert sum(sig.s > n // 2 for sig in sigs) >= 1


def test_older_real_list_has_a_different_node_shape_and_fails_closed() -> None:
    """Version 3 (issued 2026-10-05) is a real, validly signed list whose nodes are bare
    URL strings, the shape the hub's loader expects (ADR-0009, 'What to watch'); version 4
    switched to {url, country, organisation} objects. Its signatures verify, so the shape
    is what stops it."""
    v3, v3_sig = _read("tnl.v3.json"), _read("tnl.v3.json.sig")
    custodians = {}
    for entry in _json.loads(KEYS)["keys"]:
        key = _openpgp.read_public_key_block(entry["publicKey"])
        custodians[key.fingerprint] = key
    signers = _openpgp.verified_signers(_openpgp.read_signatures(v3_sig), v3, custodians)
    assert signers == frozenset(custodians)
    for floor in (LIST_VERSION_FLOOR, 1):
        with pytest.raises(NodeListMalformed, match="exactly the members"):
            _verify(tnl=v3, tnl_sig=v3_sig, list_floor=floor)


def test_import_needs_neither_httpx_nor_the_ebsi_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    for name in [m for m in sys.modules if m == "openvc_ebsi" or m.startswith("openvc_ebsi.")]:
        monkeypatch.delitem(sys.modules, name)
    fresh = importlib.import_module("openvc_ebsi.nodes")
    assert fresh.verify_node_list is not verify_node_list     # really re-imported
    assert "openvc_ebsi.http" not in sys.modules
    assert sys.modules["httpx"] is None


# --------------------------------------------------------------------------------------
# negatives on the real chain: tampering
# --------------------------------------------------------------------------------------
def test_a_changed_host_name_in_the_list_is_a_signature_error() -> None:
    forged = TNL.replace(b"api.ebsi.edelivery.lt", b"api.ebsi.evil-attacker.x", 1)
    assert forged != TNL
    with pytest.raises(NodeListSignatureError):
        _verify(tnl=forged)


@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_one_flipped_bit_in_tnl_json_is_a_signature_error(where: str) -> None:
    index = {"first": 0, "middle": len(TNL) // 2, "last": len(TNL) - 1}[where]
    with pytest.raises(NodeListSignatureError):
        _verify(tnl=_flip(TNL, index))


@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_one_flipped_bit_in_trusted_keys_json_is_a_signature_error(where: str) -> None:
    index = {"first": 0, "middle": len(KEYS) // 2, "last": len(KEYS) - 1}[where]
    with pytest.raises(NodeListSignatureError):
        _verify(keys=_flip(KEYS, index))


def test_an_appended_newline_is_a_signature_error_for_both_documents() -> None:
    with pytest.raises(NodeListSignatureError):
        _verify(tnl=TNL + b"\n")
    with pytest.raises(NodeListSignatureError):
        _verify(keys=KEYS + b"\n")


@pytest.mark.parametrize("field", ["s", "r", "prefix", "hashed"])
@pytest.mark.parametrize("which", ["tnl_sig", "keys_sig"])
def test_one_flipped_bit_inside_a_signature_is_a_signature_error(which: str, field: str) -> None:
    sig_file = TNL_SIG if which == "tnl_sig" else KEYS_SIG
    loc = _locate(sig_file, 0)
    # the hashed area starts with the issuer-fingerprint subpacket (a flip there would
    # change WHO signed, which is a different failure); flip a creation-time byte instead
    index = {"s": loc["s"] + 5, "r": loc["r"] + 5, "prefix": loc["prefix"] + 1,
             "hashed": loc["hashed"] + 23 + 4}[field]
    with pytest.raises(NodeListSignatureError):
        _verify(**{which: _flip(sig_file, index, 3)})


def test_the_s_flip_gets_past_the_digest_prefix_check() -> None:
    """The flipped-s case must be rejected by ECDSA itself, not by the cheap 16-bit prefix
    comparison: the prefix still equals the left bits of the recomputed digest."""
    key = _openpgp.read_public_key_block(
        _json.loads(KEYS)["keys"][0]["publicKey"])
    sig_file = TNL_SIG
    for n in (0, 1):
        sigs = _openpgp.read_signatures(sig_file)
        if sigs[n].signer == key.fingerprint:
            break
    else:                                                    # pragma: no cover
        raise AssertionError("custodian 0 not among the recorded signers")
    bad = _openpgp.read_signatures(_flip(sig_file, _locate(sig_file, n)["s"] + 5, 3))[n]
    assert hashlib.sha256(TNL + bad.suffix).digest()[:2] == bad.prefix
    assert _openpgp.verify(sigs[n], TNL, key) is True
    assert _openpgp.verify(bad, TNL, key) is False


def test_a_high_s_malleation_of_a_good_signature_still_verifies_identically() -> None:
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    loc = _locate(KEYS_SIG, 0)
    s_len = (int.from_bytes(KEYS_SIG[loc["s"] - 2:loc["s"]], "big") + 7) // 8
    s = int.from_bytes(KEYS_SIG[loc["s"]:loc["s"] + s_len], "big")
    other = n - s                                           # the other half: same signature
    other_bits = other.bit_length()
    patched = (KEYS_SIG[:loc["s"] - 2] + other_bits.to_bytes(2, "big")
               + other.to_bytes((other_bits + 7) // 8, "big"))
    patched += KEYS_SIG[loc["s"] + s_len:]
    patched = patched[:1] + bytes([len(patched) - 2]) + patched[2:]
    assert patched != KEYS_SIG
    assert _verify(keys_sig=patched) == _verify()


def test_the_unhashed_area_is_malleable_and_changes_nothing() -> None:
    """The unhashed issuer key ID (type 16) is not covered by the signature and is never
    read: editing it must give the identical result (ADR-0009 measured the same)."""
    sig_file = TNL_SIG
    loc = _locate(sig_file, 0)
    area = loc["hashed"] + loc["hashed_len"] + 2          # [length 9][type 16][8 octets]
    assert sig_file[area:area + 2] == b"\x09\x10"
    edited = bytearray(sig_file)
    for i in range(8):
        edited[area + 2 + i] ^= 0xFF
    assert bytes(edited) != sig_file
    assert _verify(tnl_sig=bytes(edited)) == _verify()


def test_a_replaced_anchor_is_a_signature_error() -> None:
    other = _openpgp.read_public_key_block(_json.loads(KEYS)["keys"][0]["publicKey"])
    wrong = Anchor(other.fingerprint, other.curve, other.point)
    with pytest.raises(NodeListSignatureError):
        _verify(anchor=wrong)


def test_the_wrong_file_for_a_signature_is_rejected_with_the_right_class() -> None:
    with pytest.raises(NodeListSignatureError):                     # custodian sigs for keys
        _verify(keys_sig=TNL_SIG)
    with pytest.raises(NodeListSignatureError):                     # swapped documents
        _verify(tnl=KEYS, keys=TNL)
    # the key list's signature offered for the node list: the anchor is not a custodian,
    # so it is an unknown signer, ignored, and 0 of 2 custodians signed
    with pytest.raises(NodeListThresholdError, match="0 distinct"):
        _verify(tnl_sig=KEYS_SIG)


def test_below_threshold_is_a_threshold_error() -> None:
    one = TNL_SIG[:FIRST_SIG_PACKET]
    assert len(_openpgp.read_signatures(one)) == 1
    with pytest.raises(NodeListThresholdError, match="1 distinct"):
        _verify(tnl_sig=one)
    with pytest.raises(NodeListThresholdError, match="1 distinct"):     # the same one twice
        _verify(tnl_sig=one + one)
    with pytest.raises(NodeListThresholdError):
        _verify(min_threshold=3)
    assert _verify(min_threshold=2) is not None
    assert _verify(min_threshold=None) is not None


def test_the_same_signer_twice_still_needs_both_to_verify() -> None:
    one = TNL_SIG[:FIRST_SIG_PACKET]
    loc = _locate(one, 0)
    broken = _flip(one, loc["s"] + 5, 3)
    with pytest.raises(NodeListSignatureError):
        _verify(tnl_sig=one + broken)


def test_an_unknown_signer_is_ignored_even_with_garbage_values() -> None:
    """A signature whose hashed issuer fingerprint is nobody's is skipped and no ECDSA runs
    on it; it must still parse, so the garbage here is a well-formed MPI pair."""
    first = bytearray(TNL_SIG[:FIRST_SIG_PACKET])
    loc = _locate(bytes(first), 0)
    stranger = bytearray(first)
    stranger[loc["hashed"] + 3] ^= 0x55           # the first fingerprint octet: a stranger
    stranger[loc["s"] + 3] ^= 0xFF                # garbage s (bit count still right: top byte kept)
    extended = TNL_SIG + bytes(stranger)
    assert _verify(tnl_sig=extended) == _verify()
    # but the same garbage under an ALLOWED fingerprint rejects the whole file
    allowed_garbage = bytearray(first)
    allowed_garbage[loc["s"] + 3] ^= 0xFF
    with pytest.raises(NodeListSignatureError):
        _verify(tnl_sig=TNL_SIG + bytes(allowed_garbage))


# --------------------------------------------------------------------------------------
# rollback, floors, time
# --------------------------------------------------------------------------------------
OTHER = "0" * 64


def test_list_rollback_pairs() -> None:
    for bad in (Accepted(5, OTHER), Accepted(4, OTHER)):
        with pytest.raises(NodeListRollback):
            _verify(last_accepted_list=bad)
    for good in (Accepted(4, SHA256["tnl.json"]), Accepted(3, OTHER), Accepted(1, OTHER)):
        assert _verify(last_accepted_list=good).version == 4


def test_key_list_rollback_pairs() -> None:
    # the same four cases, minus "lower than 1", which cannot exist
    for bad in (Accepted(2, OTHER), Accepted(1, OTHER)):
        with pytest.raises(NodeListRollback):
            _verify(last_accepted_keys=bad)
    assert _verify(last_accepted_keys=Accepted(1, SHA256["trusted-keys.json"])).keys_version == 1


def test_floors() -> None:
    with pytest.raises(NodeListRollback):
        _verify(list_floor=5)
    with pytest.raises(NodeListRollback):
        _verify(keys_floor=2)
    assert _verify(list_floor=4, keys_floor=1) is not None            # equal passes


def test_expiry_boundary() -> None:
    with pytest.raises(NodeListExpired):
        _verify(now=EXPIRES)
    with pytest.raises(NodeListExpired):
        _verify(now=EXPIRES + SECOND)
    assert _verify(now=EXPIRES - SECOND).expires == EXPIRES


def test_not_yet_valid_boundary() -> None:
    assert _verify(now=ISSUED - timedelta(seconds=300)) is not None   # exactly 300 s passes
    with pytest.raises(NodeListNotYetValid):
        _verify(now=ISSUED - timedelta(seconds=301))


def test_max_age_boundary() -> None:
    age = NOW - ISSUED
    assert _verify(max_age=age) is not None                           # exactly equal passes
    with pytest.raises(NodeListStale):
        _verify(max_age=age - SECOND)
    assert _verify(max_age=None) is not None


def test_naive_now_is_utc_and_an_offset_now_is_converted() -> None:
    naive = NOW.replace(tzinfo=None)
    assert _verify(now=naive) == _verify()
    plus_two = NOW.astimezone(timezone(timedelta(hours=2)))
    assert _verify(now=plus_two) == _verify()
    with pytest.raises(NodeListExpired):
        _verify(now=EXPIRES.replace(tzinfo=None))


# --------------------------------------------------------------------------------------
# authenticate before parse
# --------------------------------------------------------------------------------------
def test_an_unauthenticated_key_list_is_never_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("parsed bytes that were not authenticated")

    monkeypatch.setattr(_json, "loads", forbidden)
    monkeypatch.setattr(_openpgp, "read_public_key_block", forbidden)
    junk = b"this is not JSON \xff\xfe"
    with pytest.raises(NodeListSignatureError):          # not Malformed: the signature came first
        _verify(keys=junk)
    with pytest.raises(NodeListSignatureError):
        _verify(keys=junk, keys_sig=_flip(KEYS_SIG, _locate(KEYS_SIG, 0)["s"] + 5, 3))


def test_an_unauthenticated_node_list_is_never_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    real = _json.loads

    def spy(data: Any, **kwargs: Any) -> Any:
        seen.append(data)
        return real(data, **kwargs)

    monkeypatch.setattr(_json, "loads", spy)
    # the anchor's signature, offered for tnl.json: no custodian signed, so 0 of 2
    with pytest.raises(NodeListThresholdError):
        _verify(tnl=b"not json at all", tnl_sig=KEYS_SIG)
    assert len(seen) == 1 and seen[0].lstrip().startswith("{")      # only trusted-keys.json
    assert '"threshold"' in seen[0]


# --------------------------------------------------------------------------------------
# arguments
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("environment", [
    "production", "conformance", "", "Prod", "PROD", " prod", "prod ", "pilot\n", "legacy-pilot",
    None, 3, b"prod", ["prod"], ("prod",), {"prod"}, True, 1.5])
def test_unknown_environments_are_config_errors(environment: Any) -> None:
    with pytest.raises(NodeListConfigError, match="environment"):
        _verify(environment=environment)


@pytest.mark.parametrize("now", [None, 0, 1760000000, "2026-10-16T12:00:00Z", 1.5, b"x", object()])
def test_now_must_be_a_datetime(now: Any) -> None:
    with pytest.raises(NodeListConfigError, match="now"):
        _verify(now=now)


@pytest.mark.parametrize("name", ["tnl", "tnl_sig", "keys", "keys_sig"])
@pytest.mark.parametrize("bad", ["a string", None, 5, [1, 2], {"a": 1}])
def test_inputs_must_be_bytes(name: str, bad: Any) -> None:
    with pytest.raises(NodeListConfigError, match=name):
        _verify(**{name: bad})


def test_a_str_input_is_refused_not_encoded() -> None:
    with pytest.raises(NodeListConfigError, match="as served"):
        _verify(tnl=TNL.decode("utf-8"))


def test_byte_like_inputs_are_accepted_and_read_once() -> None:
    base = _verify()
    assert _verify(tnl=bytearray(TNL), keys=memoryview(KEYS)) == base

    class Lying(bytes):
        """A bytes subclass whose Python-level reads answer differently each time."""
        reads = 0

        def __len__(self) -> int:
            Lying.reads += 1
            return 3

        def __getitem__(self, key: Any) -> Any:
            Lying.reads += 1
            return b"x"

        def hex(self, *a: Any, **k: Any) -> str:               # type: ignore[override]
            Lying.reads += 1
            return "00"

        def decode(self, *a: Any, **k: Any) -> str:            # type: ignore[override]
            Lying.reads += 1
            return "{}"

        def __bytes__(self) -> bytes:                          # what bytes(x) would consult
            Lying.reads += 1
            return b"{}"

        def __iter__(self) -> Any:
            Lying.reads += 1
            return iter(b"{}")

    lying = Lying(TNL)
    assert _verify(tnl=lying) == base
    assert Lying.reads == 0                      # none of its overrides was ever consulted


def test_buffers_that_are_not_flat_bytes_are_config_errors() -> None:
    import array
    two_dim = memoryview(bytearray(TNL[:16])).cast("B", shape=[4, 4])
    released = memoryview(TNL)
    released.release()
    for bad in (array.array("H", [1, 2, 3]), two_dim, released):
        with pytest.raises(NodeListConfigError, match="tnl"):
            _verify(tnl=bad)
    strided = memoryview(bytearray(TNL * 2))[::2]            # 1-D, one byte per item: copied
    with pytest.raises(NodeListSignatureError):
        _verify(tnl=strided)


@pytest.mark.parametrize("bad", [
    "x", (4, "a" * 64), {"version": 4}, 4, b"x", Accepted])
def test_last_accepted_must_be_an_accepted_or_none(bad: Any) -> None:
    for name in ("last_accepted_list", "last_accepted_keys"):
        with pytest.raises(NodeListConfigError, match=name):
            _verify(**{name: bad})


@pytest.mark.parametrize("version,sha", [
    (0, "a" * 64), (-1, "a" * 64), (True, "a" * 64), (1.0, "a" * 64), ("4", "a" * 64),
    (2 ** 63, "a" * 64), (None, "a" * 64),
    (4, "A" * 64), (4, "a" * 63), (4, "a" * 65), (4, ("a" * 63) + "\n"), (4, ""), (4, None),
    (4, b"a" * 64), (4, "g" * 64)])
def test_accepted_validates_at_construction(version: Any, sha: Any) -> None:
    with pytest.raises(NodeListConfigError):
        Accepted(version, sha)


def test_an_accepted_subclass_that_lies_is_read_once() -> None:
    class Liar(Accepted):
        flips = 0

        @property                                               # type: ignore[override]
        def version(self) -> int:
            Liar.flips += 1
            return 4 if Liar.flips % 2 else 400

    liar = Liar.__new__(Liar)
    object.__setattr__(liar, "sha256", SHA256["tnl.json"])
    # one read per call: it sees 4 or 400 consistently within the call, never a mix
    _verify(last_accepted_list=liar)                  # reads 4: the same bytes pass
    with pytest.raises(NodeListRollback):
        _verify(last_accepted_list=liar)              # reads 400: a rollback, consistently


@pytest.mark.parametrize("bad", [0, -1, True, False, 1.0, "2", 2.5, [], object()])
def test_floors_and_min_threshold_must_be_positive_ints(bad: Any) -> None:
    for name in ("list_floor", "keys_floor", "min_threshold"):
        with pytest.raises(NodeListConfigError, match=name):
            _verify(**{name: bad})


@pytest.mark.parametrize("bad", [
    timedelta(0), timedelta(seconds=-1), 0, 3600, 86400.0, "1d", True, object()])
def test_max_age_must_be_a_positive_timedelta(bad: Any) -> None:
    with pytest.raises(NodeListConfigError, match="max_age"):
        _verify(max_age=bad)


def test_the_anchor_must_be_a_well_formed_anchor() -> None:
    point = EUROPEUM_KEY_LIST_ANCHOR.public_point
    fp = EUROPEUM_KEY_LIST_ANCHOR.fingerprint
    bad: list[Any] = [
        (fp.lower(), "P-256", point), (fp[:-1], "P-256", point), (fp + "0", "P-256", point),
        (fp, "P-384", point), (fp, "p-256", point), (fp, "secp256r1", point),
        (fp, "P-256", point[:-1]), (fp, "P-256", b"\x03" + point[1:33]),
        (fp, "P-256", b"\x04" + b"\x01" * 64),           # not on the curve
        (fp, "P-256", point.hex()), (fp, "P-256", bytearray(point)),
        (None, "P-256", point), (fp, None, point), (fp, "P-256", None),
    ]
    for fingerprint, curve, public_point in bad:
        with pytest.raises(NodeListConfigError):
            Anchor(fingerprint, curve, public_point)
    for not_an_anchor in (None, "ACCC", (fp, "P-256", point), object()):
        with pytest.raises(NodeListConfigError, match="anchor"):
            _verify(anchor=not_an_anchor)


@pytest.mark.parametrize("block", [None, 5, b"\xff\xfe", b"", "", "not armor"])
def test_anchor_from_a_bad_key_block_is_a_config_error(block: Any) -> None:
    with pytest.raises(NodeListConfigError, match="anchor"):
        Anchor.from_public_key_block(block)


def test_an_anchor_block_that_is_not_the_profile_is_a_config_error() -> None:
    # the custodian blocks ARE in profile; a block with its self-signature cut off at the
    # armor level is not valid armor
    broken = ASC.replace(b"-----END", b"-----ENX")
    with pytest.raises(NodeListConfigError):
        Anchor.from_public_key_block(broken)


def test_every_error_is_an_ebsi_and_openvc_error() -> None:
    for cls in (NodeListConfigError, NodeListMalformed, OpenPgpError, NodeListSignatureError,
                NodeListThresholdError, NodeListRollback, NodeListExpired,
                NodeListNotYetValid, NodeListStale, NodeListEnvironmentMissing):
        assert issubclass(cls, NodeListError)
    assert issubclass(NodeListError, EbsiError) and issubclass(EbsiError, OpenvcError)
    assert issubclass(OpenPgpError, NodeListMalformed)
    # the leaves are siblings: an expired list is not "malformed", a forgery is not "stale"
    assert not issubclass(NodeListExpired, NodeListMalformed)
    assert not issubclass(NodeListSignatureError, NodeListMalformed)


def test_size_caps() -> None:
    with pytest.raises(NodeListMalformed, match="cap"):
        _verify(tnl=b"x" * (nodes_mod.MAX_LIST_BYTES + 1))
    with pytest.raises(NodeListMalformed, match="cap"):
        _verify(keys=b"x" * (nodes_mod.MAX_KEYS_BYTES + 1))
    for name in ("tnl_sig", "keys_sig"):
        with pytest.raises(NodeListMalformed, match="cap"):
            _verify(**{name: b"x" * (_openpgp.MAX_SIGNATURE_FILE_BYTES + 1)})
    # the live files are far under every cap
    assert len(TNL) * 30 < nodes_mod.MAX_LIST_BYTES * 1.1
    assert len(KEYS) * 30 < nodes_mod.MAX_KEYS_BYTES * 1.1


def test_the_whitespace_sets_are_what_ecmascript_matches() -> None:
    """The publisher's schema pattern for `organisation` is ^\\S(.*\\S)?$ (ECMAScript): the
    code points `\\s` matches and the ones `.` refuses, measured with node over the whole
    code space on 2026-10-16 (not recalled)."""
    measured = [0x9, 0xA, 0xB, 0xC, 0xD, 0x20, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028,
                0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF]
    assert nodes_mod._ECMA_SPACE == frozenset(map(chr, measured))
    assert nodes_mod._ECMA_LINE_TERMINATORS == frozenset(map(chr, (0xA, 0xD, 0x2028, 0x2029)))


def test_the_four_byte_strings_cannot_be_passed_positionally() -> None:
    # keyword-only on purpose: a swapped pair (tnl and keys) must be a loud Python error
    with pytest.raises(TypeError):
        verify_node_list(TNL, TNL_SIG, KEYS, KEYS_SIG)                  # type: ignore[misc]
    with pytest.raises(TypeError, match="last_accepted_list"):
        verify_node_list(tnl=TNL, tnl_sig=TNL_SIG, keys=KEYS, keys_sig=KEYS_SIG,
                         environment="prod", now=NOW)                    # type: ignore[call-arg]
