"""
openvc.proof.ecdsa_sd — Data Integrity cryptosuite ``ecdsa-sd-2023``
(W3C VC Data Integrity ECDSA Cryptosuites): **selective disclosure** over P-256.

The third Data Integrity cryptosuite alongside ``eddsa-rdfc-2022``. Where that one
signs the whole canonical document once, ecdsa-sd-2023 lets an issuer sign each
statement so a holder can later reveal only a chosen subset:

    issuer  -> add_base_proof(doc, mandatoryPointers)     (a base proof)
    holder  -> derive_proof(base, selectivePointers)      (a derived proof)
    verifier-> verify(derived)                            (checks the disclosed subset)

The proof value is a multibase (``u``) CBOR blob. Base proof:
``0xd95d00 ‖ CBOR([baseSignature, publicKey, hmacKey, signatures, mandatoryPointers])``;
derived proof:
``0xd95d01 ‖ CBOR([baseSignature, publicKey, signatures, compressedLabelMap,
mandatoryIndexes])``. Blank-node labels are blinded with HMAC-SHA256; per-statement
signatures use an ephemeral proof-scoped P-256 key.

Status: interop-validated against the official W3C ``vc-di-ecdsa`` test vectors —
``verify`` accepts reference-produced derived proofs, and the issuer-side
canonical N-Quads and ``proofHash`` / ``mandatoryHash`` match the recorded
intermediates byte for byte (``tests/fixtures/ecdsa_sd/``). ECDSA signatures are
randomised, so — unlike ``eddsa-rdfc-2022`` — interop is shown this way rather
than by reproducing a fixed proof value.

This module reuses the P-256 backend and the SSRF-safe offline canonicalization of
the other suites; it needs the ``[data-integrity]`` extra (pyld). CBOR is a small
hand-rolled codec for the fixed proof-value shape (no new dependency), like the
project's own varint/base58.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ..keys import P256SigningKey, verify_signature
from ._verify_common import (
    DEFAULT_LEEWAY_S,
    CredentialExpired,
    CredentialNotYetValid,
    KeyResolutionError,
    MalformedTimestamp,
    ProofPurposeMismatch,
    check_proof_purpose,
    check_validity_window,
    resolve_verification_key,
)
from .contexts import document_loader
from .vc_jwt import ProofError, SigningKey

BASE_PROOF_HEADER = bytes((0xD9, 0x5D, 0x00))
DERIVED_PROOF_HEADER = bytes((0xD9, 0x5D, 0x01))
CRYPTOSUITE = "ecdsa-sd-2023"
PROOF_TYPE = "DataIntegrityProof"
_P256_MULTIKEY_PREFIX = bytes((0x80, 0x24))     # multicodec p256-pub (0x1200) varint


class EcdsaSdError(ProofError): ...
class ProofValueMalformed(EcdsaSdError): ...


# --------------------------------------------------------------------------- #
# base64url + multibase
# --------------------------------------------------------------------------- #

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _mb_encode(data: bytes) -> str:
    return "u" + _b64url_encode(data)               # multibase base64url-no-pad


def _mb_decode(value: str) -> bytes:
    if not value.startswith("u"):
        raise ProofValueMalformed("proofValue must be multibase base64url ('u')")
    return _b64url_decode(value[1:])


# --------------------------------------------------------------------------- #
# minimal CBOR (RFC 8949) for the fixed proof-value shape
#   supported: unsigned int, byte string, text string, array, map(int->bytes)
# --------------------------------------------------------------------------- #

def _cbor_head(major: int, n: int) -> bytes:
    mt = major << 5
    if n < 24:
        return bytes((mt | n,))
    if n < 0x100:
        return bytes((mt | 24, n))
    if n < 0x10000:
        return bytes((mt | 25,)) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes((mt | 26,)) + n.to_bytes(4, "big")
    return bytes((mt | 27,)) + n.to_bytes(8, "big")


def cbor_encode(obj: Any) -> bytes:
    if isinstance(obj, bool):                       # bool is an int subclass — reject
        raise EcdsaSdError("CBOR: booleans are not part of the proof-value shape")
    if isinstance(obj, int):
        if obj < 0:
            raise EcdsaSdError("CBOR: only unsigned integers are supported")
        return _cbor_head(0, obj)
    if isinstance(obj, (bytes, bytearray)):
        return _cbor_head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(obj, list):
        return _cbor_head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        # canonical: keys sorted ascending (all keys are unsigned ints here).
        items = sorted(obj.items())
        return _cbor_head(5, len(items)) + b"".join(
            cbor_encode(k) + cbor_encode(v) for k, v in items)
    raise EcdsaSdError(f"CBOR: unsupported type {type(obj).__name__}")


def _cbor_read_head(data: bytes, i: int) -> tuple[int, int, int]:
    if i >= len(data):
        raise ProofValueMalformed("CBOR: truncated")
    ib = data[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        return major, info, i
    nbytes = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if nbytes is None:
        raise ProofValueMalformed("CBOR: unsupported additional-info")
    if i + nbytes > len(data):
        raise ProofValueMalformed("CBOR: truncated length")
    return major, int.from_bytes(data[i:i + nbytes], "big"), i + nbytes


def _cbor_dec(data: bytes, i: int) -> tuple[Any, int]:
    major, n, i = _cbor_read_head(data, i)
    if major == 0:
        return n, i
    if major == 2:
        if i + n > len(data):
            raise ProofValueMalformed("CBOR: truncated byte string")
        return data[i:i + n], i + n
    if major == 3:
        if i + n > len(data):
            raise ProofValueMalformed("CBOR: truncated text string")
        return data[i:i + n].decode("utf-8"), i + n
    if major == 4:
        out = []
        for _ in range(n):
            item, i = _cbor_dec(data, i)
            out.append(item)
        return out, i
    if major == 5:
        out_map: dict[Any, Any] = {}
        for _ in range(n):
            key, i = _cbor_dec(data, i)
            val, i = _cbor_dec(data, i)
            out_map[key] = val
        return out_map, i
    raise ProofValueMalformed(f"CBOR: unsupported major type {major}")


def cbor_decode(data: bytes) -> Any:
    obj, i = _cbor_dec(data, 0)
    if i != len(data):
        raise ProofValueMalformed("CBOR: trailing bytes after the top-level item")
    return obj


# --------------------------------------------------------------------------- #
# P-256 ephemeral public key <-> multikey bytes (multicodec 0x1200 + compressed)
# --------------------------------------------------------------------------- #

def p256_public_multikey(jwk: dict[str, Any]) -> bytes:
    """A P-256 public JWK -> 35-byte multikey (0x8024 ‖ 33-byte compressed point)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise EcdsaSdError("ephemeral key is not a P-256 EC JWK")
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    from cryptography.hazmat.primitives import serialization
    compressed = pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return _P256_MULTIKEY_PREFIX + compressed


def p256_multikey_to_jwk(multikey: bytes) -> dict[str, Any]:
    """A 35-byte P-256 multikey -> public JWK."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if not multikey.startswith(_P256_MULTIKEY_PREFIX) or len(multikey) != 35:
        raise ProofValueMalformed("not a 35-byte P-256 multikey")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), multikey[len(_P256_MULTIKEY_PREFIX):])
    nums = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": _b64url_encode(nums.x.to_bytes(32, "big")),
            "y": _b64url_encode(nums.y.to_bytes(32, "big"))}


# --------------------------------------------------------------------------- #
# HMAC blank-node label map + label-map compression
# --------------------------------------------------------------------------- #

def hmac_label(hmac_key: bytes, canonical_label: str) -> str:
    """The blinded label for a canonical blank-node id (e.g. ``c14n0``):
    ``u`` + base64url-no-pad( HMAC-SHA256(hmac_key, utf8(label)) )."""
    digest = hmac.new(hmac_key, canonical_label.encode("utf-8"), hashlib.sha256).digest()
    return _mb_encode(digest)


def compress_label_map(label_map: dict[str, str]) -> dict[int, bytes]:
    """{"c14nN": "u<b64url>"} -> {N: <raw digest bytes>} for the derived proof."""
    out: dict[int, bytes] = {}
    for key, value in label_map.items():
        if not key.startswith("c14n"):
            raise EcdsaSdError(f"label map key {key!r} is not a c14n label")
        out[int(key[len("c14n"):])] = _mb_decode(value)
    return out


def decompress_label_map(compressed: dict[int, bytes]) -> dict[str, str]:
    """{N: <raw digest bytes>} -> {"c14nN": "u<b64url>"} for verification."""
    return {f"c14n{index}": _mb_encode(digest) for index, digest in compressed.items()}


# --------------------------------------------------------------------------- #
# proof-value serialization
# --------------------------------------------------------------------------- #

def serialize_base_proof(
    *, base_signature: bytes, public_key: bytes, hmac_key: bytes,
    signatures: list[bytes], mandatory_pointers: list[str],
) -> str:
    body = cbor_encode(
        [base_signature, public_key, hmac_key, signatures, mandatory_pointers])
    return _mb_encode(BASE_PROOF_HEADER + body)


def parse_base_proof(proof_value: str) -> dict[str, Any]:
    raw = _mb_decode(proof_value)
    if not raw.startswith(BASE_PROOF_HEADER):
        raise ProofValueMalformed("not an ecdsa-sd-2023 base proof (bad header)")
    parts = cbor_decode(raw[len(BASE_PROOF_HEADER):])
    if not isinstance(parts, list) or len(parts) != 5:
        raise ProofValueMalformed("base proof must decode to a 5-element array")
    base_signature, public_key, hmac_key, signatures, mandatory_pointers = parts
    return {"base_signature": base_signature, "public_key": public_key,
            "hmac_key": hmac_key, "signatures": signatures,
            "mandatory_pointers": mandatory_pointers}


def serialize_derived_proof(
    *, base_signature: bytes, public_key: bytes, signatures: list[bytes],
    label_map: dict[str, str], mandatory_indexes: list[int],
) -> str:
    body = cbor_encode([
        base_signature, public_key, signatures,
        compress_label_map(label_map), mandatory_indexes])
    return _mb_encode(DERIVED_PROOF_HEADER + body)


def parse_derived_proof(proof_value: str) -> dict[str, Any]:
    raw = _mb_decode(proof_value)
    if not raw.startswith(DERIVED_PROOF_HEADER):
        raise ProofValueMalformed("not an ecdsa-sd-2023 derived proof (bad header)")
    parts = cbor_decode(raw[len(DERIVED_PROOF_HEADER):])
    if not isinstance(parts, list) or len(parts) != 5:
        raise ProofValueMalformed("derived proof must decode to a 5-element array")
    base_signature, public_key, signatures, compressed_map, mandatory_indexes = parts
    return {"base_signature": base_signature, "public_key": public_key,
            "signatures": signatures,
            "label_map": decompress_label_map(compressed_map),
            "mandatory_indexes": mandatory_indexes}


class UnsupportedCryptosuite(EcdsaSdError): ...
class ProofMalformed(EcdsaSdError): ...
class SignatureInvalid(EcdsaSdError): ...


# The post-signature policy failures verify() may raise beyond signature/format
# errors, re-exported here so callers catch them from the suite they use. All
# share the ProofError base, so one `except ProofError` still catches everything.
POLICY_ERRORS = (
    CredentialExpired, CredentialNotYetValid, MalformedTimestamp,
    ProofPurposeMismatch, KeyResolutionError,
)


# --------------------------------------------------------------------------- #
# JSON-LD transform: skolemize -> canonicalize -> HMAC relabel (di-sd-primitives)
# --------------------------------------------------------------------------- #

_SKOLEM_PREFIX = "urn:bnid:"
_BNODE_RE = re.compile(r"_:[A-Za-z0-9_][A-Za-z0-9._-]*")


def _pyld() -> Any:
    try:
        from pyld import jsonld
    except ImportError as exc:                       # pragma: no cover - env dependent
        raise EcdsaSdError(
            "ecdsa-sd-2023 needs pyld: pip install 'openvc-core[data-integrity]'") from exc
    return jsonld


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _skolemize(node: Any, counter: list[int]) -> Any:
    """Give every blank node a stable ``urn:bnid:`` IRI so selection preserves
    identity across the full document and any selected subset."""
    if isinstance(node, list):
        return [_skolemize(x, counter) for x in node]
    if isinstance(node, dict):
        if "@value" in node:
            return node
        out = {k: _skolemize(v, counter) for k, v in node.items()}
        _id = out.get("@id")
        if _id is None:
            out["@id"] = f"{_SKOLEM_PREFIX}b{counter[0]}"
            counter[0] += 1
        elif isinstance(_id, str) and _id.startswith("_:"):
            out["@id"] = f"{_SKOLEM_PREFIX}{_id[2:]}"
        return out
    return node


def _deskolemize_nquads(nquads: str) -> str:
    return re.sub("<" + re.escape(_SKOLEM_PREFIX) + r"([^>]+)>", r"_:\1", nquads)


def _deskolemize_document(node: Any) -> Any:
    """Turn ``urn:bnid:X`` ``@id``/``id`` values back into ``_:X`` blank nodes."""
    if isinstance(node, list):
        return [_deskolemize_document(x) for x in node]
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in ("@id", "id") and isinstance(v, str) and v.startswith(_SKOLEM_PREFIX):
                out[k] = "_:" + v[len(_SKOLEM_PREFIX):]
            else:
                out[k] = _deskolemize_document(v)
        return out
    return node


def _canonicalize(nquads_text: str) -> tuple[list[str], dict[str, str]]:
    """(sorted canonical N-Quad lines, {input ``_:bnode`` -> ``_:c14nN``})."""
    from pyld.jsonld import JsonLdProcessor, URDNA2015
    issuer = URDNA2015()
    canonical = issuer.main(JsonLdProcessor.parse_nquads(nquads_text), {})
    text = JsonLdProcessor.to_nquads(canonical)
    lines = sorted(ln for ln in text.split("\n") if ln)
    return lines, dict(issuer.canonical_issuer.existing)


def _relabel(lines: Iterable[str], mapping: dict[str, str]) -> list[str]:
    def repl(m: "re.Match[str]") -> str:
        return mapping.get(m.group(0), m.group(0))
    return sorted(_BNODE_RE.sub(repl, ln) for ln in lines)


def _to_nquads(document: Any, loader: Any) -> str:
    return _pyld().to_rdf(
        document, {"format": "application/n-quads", "documentLoader": loader})


@dataclass
class _Transform:
    relabeled: list[str]                 # full doc: HMAC-relabeled canonical N-Quads
    skolem_to_hmac: dict[str, str]       # "_:X" -> "_:u<b64>"
    skolemized_compact: dict[str, Any]   # for JSON-pointer selection


def _transform(document: dict[str, Any], hmac_key: bytes, loader: Any) -> _Transform:
    jsonld = _pyld()
    expanded = jsonld.expand(document, {"documentLoader": loader})
    skolemized = _skolemize(expanded, [0])
    compacted = jsonld.compact(
        skolemized, document.get("@context"), {"documentLoader": loader})
    lines, id_map = _canonicalize(_deskolemize_nquads(_to_nquads(skolemized, loader)))
    c14n_to_hmac = {c14n: "_:" + hmac_label(hmac_key, c14n[len("_:"):])
                    for c14n in set(id_map.values())}
    return _Transform(
        relabeled=_relabel(lines, c14n_to_hmac),
        skolem_to_hmac={bn: c14n_to_hmac[c14n] for bn, c14n in id_map.items()},
        skolemized_compact=compacted)


def _selection_lines(
    selected: dict[str, Any], skolem_to_hmac: dict[str, str], loader: Any
) -> set[str]:
    """The HMAC-relabeled N-Quads of a selected sub-document (a subset of the full
    document's relabeled N-Quads, since blank nodes share stable skolem ids)."""
    deskolemized = _deskolemize_nquads(_to_nquads(selected, loader))
    lines = [ln for ln in deskolemized.split("\n") if ln]
    return set(_relabel(lines, skolem_to_hmac))


# --------------------------------------------------------------------------- #
# JSON Pointer selection (object paths; array-index pointers not yet supported)
# --------------------------------------------------------------------------- #

def _parse_pointer(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise EcdsaSdError(f"JSON pointer must start with '/': {pointer!r}")
    return [tok.replace("~1", "/").replace("~0", "~") for tok in pointer[1:].split("/")]


def _initial_selection(source: Any) -> dict[str, Any]:
    sel: dict[str, Any] = {}
    if isinstance(source, dict):
        for key in ("@id", "id"):
            v = source.get(key)
            if isinstance(v, str):
                sel[key] = v
        if "type" in source:
            sel["type"] = copy.deepcopy(source["type"])
    return sel


def select_json_ld(pointers: Iterable[str], document: dict[str, Any]) -> dict[str, Any] | None:
    pointers = list(pointers)
    if not pointers:
        return None
    selection = _initial_selection(document)
    if "@context" in document:
        selection["@context"] = copy.deepcopy(document["@context"])
    for pointer in pointers:
        _select_path(_parse_pointer(pointer), document, selection)
    return selection


def _select_path(tokens: list[str], source: Any, selection: dict[str, Any]) -> None:
    src: Any = source
    sel: Any = selection
    for i, tok in enumerate(tokens):
        if not isinstance(src, dict):
            raise EcdsaSdError("array-index JSON pointers are not yet supported")
        if tok not in src:
            raise EcdsaSdError(f"JSON pointer segment {tok!r} does not resolve")
        value = src[tok]
        if i == len(tokens) - 1:
            sel[tok] = copy.deepcopy(value)
        else:
            child = sel.get(tok)
            if child is None:
                child = _initial_selection(value) if isinstance(value, dict) else {}
                sel[tok] = child
            sel = child
        src = value


# --------------------------------------------------------------------------- #
# The proof suite
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedSdCredential:
    credential: dict[str, Any]     # the disclosed (revealed) document
    issuer: str | None
    subject: str | None
    proof: dict[str, Any]


def _proof_config_hash(proof: dict[str, Any], context: Any, loader: Any) -> bytes:
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    config["@context"] = context
    nquads = _pyld().normalize(
        config, {"algorithm": "URDNA2015", "format": "application/n-quads",
                 "documentLoader": loader})
    return hashlib.sha256(nquads.encode("utf-8")).digest()


def _sha256_lines(lines: list[str]) -> bytes:
    return hashlib.sha256("".join(ln + "\n" for ln in lines).encode("utf-8")).digest()


class EcdsaSdProofSuite:
    """Issue (base), derive (holder), and verify ecdsa-sd-2023 selective-disclosure
    Data Integrity proofs over P-256."""

    def __init__(self, *, leeway_s: int = DEFAULT_LEEWAY_S) -> None:
        self._leeway = leeway_s

    def add_base_proof(
        self,
        credential: dict[str, Any],
        *,
        signing_key: SigningKey,
        verification_method: str,
        mandatory_pointers: Iterable[str],
        proof_purpose: str = "assertionMethod",
        created: datetime | None = None,
        extra_contexts: Mapping[str, dict] | None = None,
    ) -> dict[str, Any]:
        """Issuer side: sign each statement so a holder can later disclose a subset.
        *mandatory_pointers* are always revealed. Needs an ES256 (P-256) key.

        Security note: the verifier's validity-window check can only see what the
        holder discloses. If this credential carries ``validFrom`` / ``validUntil``
        (or ``issuanceDate`` / ``expirationDate``) and you want a verifier to
        enforce them, include those pointers here — otherwise a holder may withhold
        the window from the derived proof and expiry goes unchecked. The W3C
        reference vectors mark the validity window mandatory for this reason."""
        if signing_key.alg != "ES256":
            raise UnsupportedCryptosuite(
                f"ecdsa-sd-2023 requires an ES256 (P-256) key, got {signing_key.alg!r}")
        if "@context" not in credential:
            raise ProofMalformed("credential has no @context to canonicalize against")
        if "proof" in credential:
            raise ProofMalformed("credential already carries a proof")

        mandatory = list(mandatory_pointers)
        loader = document_loader(extra_contexts)
        proof = {
            "type": PROOF_TYPE, "cryptosuite": CRYPTOSUITE,
            "created": _iso(created if created is not None else datetime.now(timezone.utc)),
            "verificationMethod": verification_method, "proofPurpose": proof_purpose,
        }
        proof_hash = _proof_config_hash(proof, credential["@context"], loader)

        hmac_key = secrets.token_bytes(32)
        transform = _transform(credential, hmac_key, loader)
        mandatory_set = _selection_lines(
            select_json_ld(mandatory, transform.skolemized_compact) or {},
            transform.skolem_to_hmac, loader) if mandatory else set()

        mandatory_lines = [ln for ln in transform.relabeled if ln in mandatory_set]
        non_mandatory = [ln for ln in transform.relabeled if ln not in mandatory_set]
        mandatory_hash = _sha256_lines(mandatory_lines)

        ephemeral = P256SigningKey.generate(kid="urn:ephemeral")
        public_key = p256_public_multikey(ephemeral.public_jwk())
        signatures = [ephemeral.sign((ln + "\n").encode("utf-8")) for ln in non_mandatory]
        base_signature = signing_key.sign(proof_hash + public_key + mandatory_hash)

        proof_value = serialize_base_proof(
            base_signature=base_signature, public_key=public_key, hmac_key=hmac_key,
            signatures=signatures, mandatory_pointers=mandatory)
        secured = copy.deepcopy(credential)
        secured["proof"] = dict(proof, proofValue=proof_value)
        return secured

    def derive_proof(
        self,
        secured: dict[str, Any],
        *,
        selective_pointers: Iterable[str],
        extra_contexts: Mapping[str, dict] | None = None,
    ) -> dict[str, Any]:
        """Holder side: reveal only the mandatory + *selective_pointers* statements."""
        proof = secured.get("proof")
        if not isinstance(proof, dict) or proof.get("cryptosuite") != CRYPTOSUITE:
            raise UnsupportedCryptosuite("not an ecdsa-sd-2023 base proof")
        base = parse_base_proof(proof["proofValue"])
        hmac_key = base["hmac_key"]
        mandatory = list(base["mandatory_pointers"])
        combined = mandatory + [p for p in selective_pointers if p not in mandatory]

        loader = document_loader(extra_contexts)
        unsecured = {k: v for k, v in secured.items() if k != "proof"}
        transform = _transform(unsecured, hmac_key, loader)

        mandatory_set = _selection_lines(
            select_json_ld(mandatory, transform.skolemized_compact) or {},
            transform.skolem_to_hmac, loader) if mandatory else set()
        combined_selection = select_json_ld(combined, transform.skolemized_compact) or {}

        # Base non-mandatory line -> its signature (base sig order = non-mandatory order).
        non_mandatory = [ln for ln in transform.relabeled if ln not in mandatory_set]
        sig_by_line = dict(zip(non_mandatory, base["signatures"]))

        # Reveal document + the verifier's label map, computed exactly as verify will.
        reveal = _deskolemize_document(combined_selection)
        reveal_relabeled, reveal_map, reveal_mandatory_idx = self._reveal_view(
            reveal, transform.skolem_to_hmac, combined_selection, mandatory_set, loader)

        filtered_sigs: list[bytes] = []
        for i, ln in enumerate(reveal_relabeled):
            if i in reveal_mandatory_idx:
                continue
            if ln not in sig_by_line:
                raise EcdsaSdError("a disclosed statement has no matching base signature")
            filtered_sigs.append(sig_by_line[ln])

        proof_value = serialize_derived_proof(
            base_signature=base["base_signature"], public_key=base["public_key"],
            signatures=filtered_sigs, label_map=reveal_map,
            mandatory_indexes=list(reveal_mandatory_idx))
        derived_proof = {k: v for k, v in proof.items() if k != "proofValue"}
        derived_proof["proofValue"] = proof_value
        reveal["proof"] = derived_proof
        return reveal

    def _reveal_view(
        self, reveal: dict[str, Any], skolem_to_hmac: dict[str, str],
        combined_selection: dict[str, Any], mandatory_set: set[str], loader: Any,
    ) -> tuple[list[str], dict[str, str], list[int]]:
        """The HMAC-relabeled reveal N-Quads (as the verifier will canonicalize them),
        the label map {c14nN -> u<b64>}, and the mandatory indexes."""
        c14n_lines, id_map = _canonicalize(_deskolemize_nquads(_to_nquads(reveal, loader)))
        # Chain reveal-c14n -> skolem -> HMAC label, keyed by the reveal's own bnodes.
        relabel_map = {c14n: skolem_to_hmac[bn] for bn, c14n in id_map.items()}
        label_map = {c14n[len("_:"):]: relabel_map[c14n][len("_:"):] for c14n in relabel_map}
        relabeled = _relabel(c14n_lines, relabel_map)
        mandatory_idx = [i for i, ln in enumerate(relabeled) if ln in mandatory_set]
        return relabeled, label_map, mandatory_idx

    def verify(
        self,
        derived: dict[str, Any],
        *,
        public_key_jwk: dict[str, Any] | None = None,
        resolver: Any = None,
        expected_proof_purpose: str | None = "assertionMethod",
        now: datetime | None = None,
        extra_contexts: Mapping[str, dict] | None = None,
    ) -> VerifiedSdCredential:
        """Verify a derived proof: the issuer's base signature over the mandatory
        statements, and the per-statement signatures over each disclosed one.

        Key selection and policy match :meth:`DataIntegrityProofSuite.verify`:
        *public_key_jwk* pins an operator-trusted key, else the P-256
        ``verificationMethod`` resolves via *resolver* (falling back to offline
        ``did:key``) and must be authorized for *expected_proof_purpose*. After
        the signatures verify, the proof's ``proofPurpose`` and the disclosed
        credential's validity window (with the suite's leeway, evaluated at *now*)
        are enforced — a derived proof only reveals a subset, so these bounds are
        checked against whatever the holder disclosed."""
        proof = derived.get("proof")
        if not isinstance(proof, dict):
            raise ProofMalformed("credential has no proof object")
        if proof.get("cryptosuite") != CRYPTOSUITE:
            raise UnsupportedCryptosuite(f"unsupported cryptosuite {proof.get('cryptosuite')!r}")
        parsed = parse_derived_proof(proof["proofValue"])

        loader = document_loader(extra_contexts)
        unsecured = {k: v for k, v in derived.items() if k != "proof"}
        c14n_lines, _ = _canonicalize(_deskolemize_nquads(_to_nquads(unsecured, loader)))
        relabel_map = {"_:" + k: "_:" + v for k, v in parsed["label_map"].items()}
        relabeled = _relabel(c14n_lines, relabel_map)

        mandatory_idx = set(parsed["mandatory_indexes"])
        mandatory_lines = [ln for i, ln in enumerate(relabeled) if i in mandatory_idx]
        non_mandatory = [ln for i, ln in enumerate(relabeled) if i not in mandatory_idx]

        proof_hash = _proof_config_hash(proof, derived.get("@context"), loader)
        mandatory_hash = _sha256_lines(mandatory_lines)
        to_verify = proof_hash + parsed["public_key"] + mandatory_hash

        issuer_jwk = public_key_jwk or resolve_verification_key(
            proof.get("verificationMethod"),
            proof_purpose=proof.get("proofPurpose"),
            resolver=resolver,
        )
        if not verify_signature(alg="ES256", public_jwk=issuer_jwk,
                                signing_input=to_verify, signature=parsed["base_signature"]):
            raise SignatureInvalid("base signature does not verify")

        ephemeral_jwk = p256_multikey_to_jwk(parsed["public_key"])
        if len(parsed["signatures"]) != len(non_mandatory):
            raise SignatureInvalid("disclosed statement / signature count mismatch")
        for line, sig in zip(non_mandatory, parsed["signatures"]):
            if not verify_signature(alg="ES256", public_jwk=ephemeral_jwk,
                                    signing_input=(line + "\n").encode("utf-8"), signature=sig):
                raise SignatureInvalid("a disclosed statement signature does not verify")

        check_proof_purpose(proof, expected_proof_purpose)
        check_validity_window(unsecured, proof, now=now, leeway_s=self._leeway)

        issuer = unsecured.get("issuer")
        issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
        subj = unsecured.get("credentialSubject")
        subject = subj.get("id") if isinstance(subj, dict) else None
        return VerifiedSdCredential(
            credential=derived, issuer=issuer, subject=subject, proof=proof)
