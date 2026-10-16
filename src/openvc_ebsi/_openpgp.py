"""openvc_ebsi._openpgp — the minimal OpenPGP reader behind the Trusted Nodes List.

Private. It reads exactly the profile the live Trusted Nodes List chain uses and nothing
else (ADR-0009, Option C), and every other construct is an :class:`OpenPgpError` — the
reader never guesses and never skips what it does not understand, except the packets and
subpackets listed below as deliberately ignored.

**Profile.** OpenPGP v4; ECDSA (public-key algorithm 19) over NIST P-256, the curve matched
by its exact OID; a SEC1 uncompressed point (``0x04``, validated on the curve by
``cryptography``); SHA-256 (hash algorithm 8); signature type 0x00 (binary document);
old-format packet headers with a 1-, 2- or 4-octet length. Armor is the shape the recorded
key blocks have and no other. Curve and hash are two small tables (:data:`_CURVES`,
:data:`_HASHES`), so widening either is one entry plus a test vector.

**What it reads, and what it ignores.**

* A detached-signature file (:func:`read_signatures`): only tag-2 packets, each strictly
  parsed. The signer is the *hashed* issuer-fingerprint subpacket (type 33) and nothing
  else — the unhashed area is not covered by the signature, so anyone can edit it, and it
  is walked for structure only and never interpreted. A hashed signature-expiration (3) or
  key-expiration (9) subpacket, and any critical hashed subpacket other than 2 and 33, is
  refused: a full OpenPGP library honours them, so ignoring them would accept what the
  reference verifier rejects.
* A key block (:func:`read_public_key_block`): exactly one primary key (tag 6), first;
  the fingerprint is recomputed from its material. User IDs (13) and subkeys (14) are
  skipped without their content being read, and a subkey is never a signer identity. A
  self- or binding signature (2) is not verified; it is refused only if it is a revocation
  (types 0x20, 0x28, 0x30) or carries a hashed expiration subpacket (3 or 9). Any other
  tag is refused.
* Subpackets are never recursed into: an embedded signature (type 32) is opaque bytes.

Every size and count is capped, so the work is bounded by the caps, not by the input.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from openvc_ebsi.errors import NodeListSignatureError, OpenPgpError

# ---- bounds (every one is a fail-closed cap; the live chain is far under each) ----------
MAX_SIGNATURE_FILE_BYTES = 4096      # a .sig file; the live ones are 266 and 147 bytes
MAX_ARMOR_CHARS = 12288              # one armored key block; the live ones are 1030 / 498
MAX_KEY_BLOCK_BYTES = 8192           # the same block once dearmored; live: 700 / 309 / 790
MAX_PACKETS = 32                     # packets in one file or block
MAX_SUBPACKETS = 64                  # subpackets in one area
MAX_ARMOR_LINE = 76                  # the armor line length RFC-era writers stop at; live: 64

# ---- the profile tables ------------------------------------------------------------------
_TAG_SIGNATURE = 2
_TAG_PUBLIC_KEY = 6
_TAG_USER_ID = 13
_TAG_PUBLIC_SUBKEY = 14
_ALGO_ECDSA = 19
_SIG_BINARY = 0x00
_REVOCATION_TYPES = frozenset({0x20, 0x28, 0x30})   # key, subkey, certification revocation
_SUB_CREATION_TIME = 2
_SUB_SIG_EXPIRATION = 3
_SUB_KEY_EXPIRATION = 9
_SUB_ISSUER_FINGERPRINT = 33
_UNDERSTOOD_WHEN_CRITICAL = frozenset({_SUB_CREATION_TIME, _SUB_ISSUER_FINGERPRINT})


@dataclass(frozen=True)
class _Curve:
    name: str
    curve: ec.EllipticCurve
    point_len: int       # SEC1 uncompressed: 0x04 || X || Y
    scalar_bits: int     # an r or s is at most this many bits


@dataclass(frozen=True)
class _Hash:
    name: str
    hashlib_name: str
    algorithm: type[hashes.HashAlgorithm]


# curve OID (the bytes after the length octet) -> curve; P-256 is 1.2.840.10045.3.1.7
_CURVES: dict[bytes, _Curve] = {
    bytes.fromhex("2a8648ce3d030107"): _Curve("P-256", ec.SECP256R1(), 65, 256),
}
# OpenPGP hash-algorithm id -> hash; 8 is SHA-256
_HASHES: dict[int, _Hash] = {8: _Hash("SHA-256", "sha256", hashes.SHA256)}
CURVE_NAMES: dict[str, bytes] = {c.name: oid for oid, c in _CURVES.items()}


@dataclass(frozen=True)
class PublicKey:
    """A custodian's or the anchor's primary key: its v4 fingerprint (40 upper-case hex
    characters) and the ECDSA key that verifies for it."""
    fingerprint: str
    curve: str
    point: bytes
    key: ec.EllipticCurvePublicKey = field(compare=False, repr=False)


@dataclass(frozen=True)
class Signature:
    """One parsed v4 binary signature. ``signer`` is the hashed issuer fingerprint
    (upper-case hex) or ``None`` when the hashed area names none."""
    signer: str | None
    hash_id: int         # the OpenPGP hash-algorithm id; a key of _HASHES
    prefix: bytes        # the left 16 bits of the signed digest
    suffix: bytes        # hashed header + hashed subpackets + the 0x04 0xFF trailer
    r: int
    s: int


def _fail(message: str) -> OpenPgpError:
    return OpenPgpError(message)


# ---- framing -----------------------------------------------------------------------------
def _packets(data: bytes) -> list[tuple[int, bytes]]:
    """Split *data* into ``(tag, body)`` packets. Old-format headers only; a new-format
    header, an indefinite length, a length past the end and more than
    :data:`MAX_PACKETS` packets are refused."""
    out: list[tuple[int, bytes]] = []
    pos, end = 0, len(data)
    while pos < end:
        if len(out) >= MAX_PACKETS:
            raise _fail(f"more than {MAX_PACKETS} packets")
        head = data[pos]
        if not head & 0x80:
            raise _fail("a packet header must have its high bit set")
        if head & 0x40:
            raise _fail("new-format packet headers are not accepted")
        tag, kind = (head >> 2) & 0x0F, head & 0x03
        if kind == 3:
            raise _fail("an indefinite-length packet is not accepted")
        width = (1, 2, 4)[kind]
        if pos + 1 + width > end:
            raise _fail("a packet header is cut short")
        length = int.from_bytes(data[pos + 1:pos + 1 + width], "big")
        start = pos + 1 + width
        if length > end - start:
            raise _fail("a packet length runs past the end of the data")
        out.append((tag, data[start:start + length]))
        pos = start + length
    return out


def _subpackets(area: bytes) -> list[tuple[int, bool, bytes]]:
    """Split a subpacket area into ``(type, critical, data)``, structure only."""
    out: list[tuple[int, bool, bytes]] = []
    pos, end = 0, len(area)
    while pos < end:
        if len(out) >= MAX_SUBPACKETS:
            raise _fail(f"more than {MAX_SUBPACKETS} subpackets in one area")
        first = area[pos]
        if first < 192:
            length, hdr = first, 1
        elif first < 255:
            if pos + 2 > end:
                raise _fail("a subpacket length is cut short")
            length, hdr = ((first - 192) << 8) + area[pos + 1] + 192, 2
        else:
            if pos + 5 > end:
                raise _fail("a subpacket length is cut short")
            length, hdr = int.from_bytes(area[pos + 1:pos + 5], "big"), 5
        start = pos + hdr
        if length < 1 or length > end - start:
            raise _fail("a subpacket length is zero or runs past its area")
        kind = area[start]
        out.append((kind & 0x7F, bool(kind & 0x80), area[start + 1:start + length]))
        pos = start + length
    return out


def _mpi(data: bytes, pos: int, max_bits: int) -> tuple[bytes, int]:
    """A strict multiprecision integer at *pos*: a 2-octet bit count, then exactly
    ``ceil(bits / 8)`` octets whose top bit is the counted one. Zero bits, a leading zero
    octet, a count that disagrees with the value and more than *max_bits* are refused."""
    if pos + 2 > len(data):
        raise _fail("an MPI length is cut short")
    bits = int.from_bytes(data[pos:pos + 2], "big")
    if bits < 1 or bits > max_bits:
        raise _fail(f"an MPI of {bits} bits is outside 1..{max_bits}")
    size = (bits + 7) // 8
    if pos + 2 + size > len(data):
        raise _fail("an MPI runs past the end of its packet")
    value = data[pos + 2:pos + 2 + size]
    if value[0] == 0 or 8 * (size - 1) + value[0].bit_length() != bits:
        raise _fail("an MPI bit count does not match its value")
    return value, pos + 2 + size


# ---- signatures --------------------------------------------------------------------------
def _split_v4_signature(body: bytes) -> tuple[int, int, int, bytes, int]:
    """``(type, public-key algorithm, hash algorithm, hashed area, offset after the
    unhashed area)`` of a v4 signature body, bounds-checked."""
    if len(body) < 6:
        raise _fail("a signature packet is too short")
    if body[0] != 4:
        raise _fail(f"signature version {body[0]} is not accepted (v4 only)")
    hashed_len = int.from_bytes(body[4:6], "big")
    if 6 + hashed_len + 2 > len(body):
        raise _fail("a hashed subpacket area runs past its packet")
    hashed = body[6:6 + hashed_len]
    at = 6 + hashed_len
    unhashed_len = int.from_bytes(body[at:at + 2], "big")
    if at + 2 + unhashed_len > len(body):
        raise _fail("an unhashed subpacket area runs past its packet")
    return body[1], body[2], body[3], hashed, at + 2 + unhashed_len


def _check_hashed_area(hashed: bytes, *, signature_file: bool) -> str | None:
    """Walk a hashed area and refuse the expiration subpackets (3 and 9) wherever they
    are. In a signature file (*signature_file*) it also refuses a critical subpacket this
    reader does not process and a malformed or repeated issuer fingerprint, and returns
    that fingerprint (upper-case hex) or ``None`` when there is none; in a key block the
    self-signature is not interpreted any further, so only the expirations matter."""
    signer: str | None = None
    for kind, critical, data in _subpackets(hashed):
        if kind in (_SUB_SIG_EXPIRATION, _SUB_KEY_EXPIRATION):
            raise _fail(f"a hashed expiration subpacket (type {kind}) is not accepted")
        if not signature_file:
            continue
        if critical and kind not in _UNDERSTOOD_WHEN_CRITICAL:
            raise _fail(f"a critical hashed subpacket of type {kind} is not understood")
        if kind == _SUB_ISSUER_FINGERPRINT:
            if signer is not None:
                raise _fail("two issuer-fingerprint subpackets")
            if len(data) != 21 or data[0] != 4:
                raise _fail("an issuer-fingerprint subpacket must be v4 and 21 octets")
            signer = data[1:].hex().upper()
    return signer


def _parse_signature(body: bytes) -> Signature:
    sig_type, algo, hash_id, hashed, after = _split_v4_signature(body)
    if sig_type != _SIG_BINARY:
        raise _fail(f"signature type 0x{sig_type:02x} is not accepted (binary 0x00 only)")
    if algo != _ALGO_ECDSA:
        raise _fail(f"public-key algorithm {algo} is not accepted (ECDSA 19 only)")
    if hash_id not in _HASHES:
        raise _fail(f"hash algorithm {hash_id} is not accepted (SHA-256 only)")
    signer = _check_hashed_area(hashed, signature_file=True)
    _subpackets(body[6 + len(hashed) + 2:after])        # structure only; never interpreted
    if after + 2 > len(body):
        raise _fail("a signature has no digest prefix")
    prefix = body[after:after + 2]
    bits = max(c.scalar_bits for c in _CURVES.values())
    r, pos = _mpi(body, after + 2, bits)
    s, pos = _mpi(body, pos, bits)
    if pos != len(body):
        raise _fail("trailing bytes after a signature")
    header = body[:6 + len(hashed)]
    suffix = header + b"\x04\xff" + len(header).to_bytes(4, "big")
    return Signature(signer, hash_id, prefix, suffix,
                     int.from_bytes(r, "big"), int.from_bytes(s, "big"))


def read_signatures(data: bytes) -> tuple[Signature, ...]:
    """Parse a detached-signature file: one or more v4 binary ECDSA/SHA-256 signature
    packets and nothing else."""
    if not data:
        raise _fail("an empty signature file")
    if len(data) > MAX_SIGNATURE_FILE_BYTES:
        raise _fail(f"a signature file over {MAX_SIGNATURE_FILE_BYTES} bytes")
    sigs = []
    for tag, body in _packets(data):
        if tag != _TAG_SIGNATURE:
            raise _fail(f"packet tag {tag} in a signature file (only tag 2 is accepted)")
        sigs.append(_parse_signature(body))
    return tuple(sigs)


def verify(signature: Signature, document: bytes, key: PublicKey) -> bool:
    """Whether *signature* is a valid signature by *key* over exactly *document*: the
    digest is ``H(document || hashed header || hashed subpackets || 0x04 0xFF || length)``
    with H the signature's hash (SHA-256; RFC 4880 section 5.2.4), its left 16 bits must
    equal the packet's prefix, and ECDSA is checked on it. A high ``s`` is accepted:
    OpenPGP has no low-``s`` rule and signers emit either half."""
    spec = _HASHES[signature.hash_id]
    digest = hashlib.new(spec.hashlib_name, document + signature.suffix).digest()
    if digest[:2] != signature.prefix:
        return False
    try:
        key.key.verify(utils.encode_dss_signature(signature.r, signature.s), digest,
                       ec.ECDSA(utils.Prehashed(spec.algorithm())))
    except InvalidSignature:
        return False
    return True


def verified_signers(
    signatures: tuple[Signature, ...], document: bytes, allowed: Mapping[str, PublicKey],
) -> frozenset[str]:
    """The distinct allowed primary fingerprints with a valid signature over *document*.

    A signature whose hashed issuer fingerprint is not an *allowed* key (a stranger, a
    subkey, no fingerprint) is ignored and no ECDSA runs on it. A signature that names an
    allowed key and does not verify rejects the whole file. The same signer twice counts
    once, and both signatures must verify."""
    signers: set[str] = set()
    for sig in signatures:
        key = allowed.get(sig.signer) if sig.signer is not None else None
        if key is None:
            continue
        if not verify(sig, document, key):
            raise NodeListSignatureError(
                f"a signature by allowed key {key.fingerprint} does not verify")
        signers.add(key.fingerprint)
    return frozenset(signers)


# ---- keys --------------------------------------------------------------------------------
def make_public_key(curve: str, point: bytes, fingerprint: str) -> PublicKey:
    """A :class:`PublicKey` from its parts, the point validated on the curve. The
    fingerprint is the caller's claim: :func:`read_public_key_block` recomputes it."""
    oid = CURVE_NAMES.get(curve) if type(curve) is str else None
    if oid is None:
        raise _fail("curve is not in the accepted profile")
    spec = _CURVES[oid]
    if type(point) is not bytes or len(point) != spec.point_len or point[0] != 4:
        raise _fail("the public point must be an uncompressed SEC1 point")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(spec.curve, point)
    except ValueError as exc:
        raise _fail("the public point is not on the curve") from exc
    return PublicKey(fingerprint, spec.name, point, key)


def _parse_primary_key(body: bytes) -> PublicKey:
    if len(body) < 7:
        raise _fail("a public-key packet is too short")
    if body[0] != 4:
        raise _fail(f"public-key version {body[0]} is not accepted (v4 only)")
    if body[5] != _ALGO_ECDSA:
        raise _fail(f"public-key algorithm {body[5]} is not accepted (ECDSA 19 only)")
    oid_len = body[6]
    oid = body[7:7 + oid_len]
    spec = _CURVES.get(oid) if 0 < oid_len < 255 and len(oid) == oid_len else None
    if spec is None:
        raise _fail("the curve is not in the accepted profile (NIST P-256 only)")
    point, pos = _mpi(body, 7 + oid_len, 8 * spec.point_len)
    if pos != len(body):
        raise _fail("trailing bytes after a public key")
    fingerprint = hashlib.sha1(            # an identifier here, never a security hash
        b"\x99" + len(body).to_bytes(2, "big") + body, usedforsecurity=False,
    ).hexdigest().upper()
    return make_public_key(spec.name, point, fingerprint)


def _check_key_signature(body: bytes) -> None:
    """A self- or binding signature is not verified; it is refused only when it is a
    revocation or carries a hashed expiration subpacket."""
    sig_type, _algo, _hash, hashed, _after = _split_v4_signature(body)
    if sig_type in _REVOCATION_TYPES:
        raise _fail(f"a revocation signature (type 0x{sig_type:02x}) in a key block")
    _check_hashed_area(hashed, signature_file=False)


def read_public_key_block(armored: str) -> PublicKey:
    """Dearmor and read one custodian (or anchor) key block; see the module docstring."""
    packets = _packets(dearmor(armored))
    if not packets or packets[0][0] != _TAG_PUBLIC_KEY:
        raise _fail("a key block must start with its primary public key (tag 6)")
    key = _parse_primary_key(packets[0][1])
    for tag, body in packets[1:]:
        if tag == _TAG_SIGNATURE:
            _check_key_signature(body)
        elif tag not in (_TAG_USER_ID, _TAG_PUBLIC_SUBKEY):
            raise _fail(f"packet tag {tag} in a key block")
    return key


# ---- armor -------------------------------------------------------------------------------
_ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
_ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----"
_B64_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_CRC_LINE = re.compile(r"=[A-Za-z0-9+/]{4}")


def _crc24_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
        table.append(crc & 0xFFFFFF)
    return table


_CRC24 = _crc24_table()


def crc24(data: bytes) -> int:
    """The OpenPGP armor checksum (CRC-24, initial value 0xB704CE, polynomial 0x1864CFB)."""
    crc = 0xB704CE
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFF) ^ _CRC24[((crc >> 16) ^ byte) & 0xFF]
    return crc


def dearmor(text: str) -> bytes:
    """The bytes inside one ASCII-armored public key block, in the one shape the recorded
    blocks have: the exact BEGIN line, an empty line (no armor headers), base64 lines with
    padding only on the last, an optional ``=XXXX`` CRC-24 line (verified when present),
    the exact END line and at most one final newline. LF only; anything else is refused."""
    if type(text) is not str:
        raise _fail("armor must be text")
    if len(text) > MAX_ARMOR_CHARS:
        raise _fail(f"armor over {MAX_ARMOR_CHARS} characters")
    if not text.isascii():
        raise _fail("armor must be ASCII")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) < 4 or lines[0] != _ARMOR_BEGIN or lines[1] != "" or lines[-1] != _ARMOR_END:
        raise _fail("not an armored public key block in the accepted shape")
    body = lines[2:-1]
    crc_line = body.pop() if body[-1].startswith("=") else None
    if not body:
        raise _fail("an armored block with no data")
    for i, line in enumerate(body):
        if not 1 <= len(line) <= MAX_ARMOR_LINE or _B64_LINE.fullmatch(line) is None:
            raise _fail("an armor data line is not base64")
        if "=" in line and i != len(body) - 1:
            raise _fail("base64 padding before the last armor line")
    try:
        data = base64.b64decode("".join(body), validate=True)
        crc = None
        if crc_line is not None:
            if _CRC_LINE.fullmatch(crc_line) is None:
                raise _fail("a malformed armor checksum line")
            crc = int.from_bytes(base64.b64decode(crc_line[1:], validate=True), "big")
    except binascii.Error as exc:
        raise _fail("armor is not valid base64") from exc
    if len(data) > MAX_KEY_BLOCK_BYTES:
        raise _fail(f"a key block over {MAX_KEY_BLOCK_BYTES} bytes")
    if crc is not None and crc != crc24(data):
        raise _fail("the armor checksum does not match")
    return data
