"""
openvc.did.did_webvh — verify-side resolver for the did:webvh method (DIF
Recommended DID Method v1.0).

did:webvh is did:web plus a **self-certifying, hash-chained version log**: the DID
document is not fetched as a single ``did.json`` but *replayed* from a ``did.jsonl``
log whose every entry is cryptographically bound to the one before it. Resolving
therefore means **verifying history**, not just parsing a document:

    did:webvh:{SCID}:example.com:issuers:1  ->  https://example.com/issuers/1/did.jsonl

For each log entry (one JSON object per line) this checks, fail-closed:

* **SCID** (first entry) — the identifier is the ``base58btc(multihash-sha256(JCS(...)))``
  of the genesis entry with the SCID placeholdered out; a forged genesis cannot keep
  the same SCID.
* **entryHash chain** — each ``versionId`` is ``{n}-{entryHash}`` where the hash is
  computed over the entry with its predecessor's ``versionId`` substituted in; the
  version numbers must increment by one, so an inserted/removed/reordered entry breaks
  the chain.
* **proof** — each entry carries an ``eddsa-jcs-2022`` Data Integrity proof by a key in
  the *active* ``updateKeys``; the same JCS hashData + Ed25519 verify the DI suites use.
* **key pre-rotation** — once ``nextKeyHashes`` is set, the next entry's ``updateKeys``
  must hash into it, so a compromised current key cannot rotate to an attacker key.

Verify-side only: this resolves and validates a log; it does NOT create, update, rotate
or witness one (issuer-side tooling is out of scope). A log that declares a **witness
threshold** policy is refused fail-closed — openvc does not verify witness co-signatures,
so it will not silently downgrade to the un-witnessed trust model. Dependency-light — the
JCS, multibase/multihash and Ed25519 primitives already live in the core.

SSRF note: like did:web, did:webvh is intentionally cross-host, so it takes an injected
text fetch (pass :func:`openvc.fetch.https_text_fetch` for the SSRF-guarded one, or use
:func:`openvc.fetch.default_did_webvh_resolver`). Never route it through the EBSI
client's host allow-list.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from ..multibase import MultibaseError, b58btc_encode, decode_multibase, read_varint
from ..proof._jcs import JcsError, canonicalize
from .base import DidDocument, DidResolutionError, parse_did_document
from .did_web import _did_web_url  # reuse the did:web host/path mapping (SSRF-neutral, pure)

# A did.jsonl is JSON Lines TEXT (not one JSON object), so this resolver takes a text
# fetch — Callable[[str], str] — not the JSON-object fetch did:web uses.
TextFetch = Callable[[str], str]
AsyncTextFetch = Callable[[str], Awaitable[str]]

_SCID_PLACEHOLDER = "{SCID}"
_MULTIHASH_SHA256_PREFIX = b"\x12\x20"      # multihash: sha2-256 (0x12), 32-byte digest (0x20)
_ED25519_MULTICODEC = 0xED                  # multicodec ed25519-pub varint head
_EDDSA_JCS = "eddsa-jcs-2022"
_MAX_LOG_ENTRIES = 1000          # bound a runaway log (the fetch already bounds total bytes)


class DidWebvhError(DidResolutionError):
    """A did:webvh log is malformed or fails a history/proof/pre-rotation check."""


# --------------------------------------------------------------------------- #
# identifier -> URL
# --------------------------------------------------------------------------- #

def _did_webvh_url(did: str) -> str:
    """Map a ``did:webvh`` identifier to its ``did.jsonl`` URL.

    The identifier is ``did:webvh:{SCID}:{did:web-style host+path}``; dropping the SCID
    segment leaves exactly a did:web identifier, so the host/path/``%3A``-port mapping is
    reused — only the file is ``did.jsonl`` (versioned log) instead of ``did.json``."""
    msi = did[len("did:webvh:"):]
    scid, _, rest = msi.partition(":")
    if not scid or not rest:
        raise DidWebvhError("did:webvh must be did:webvh:{scid}:{domain}[:path...]")
    # Reuse did:web's mapping on the post-SCID remainder, then swap the filename.
    web_url = _did_web_url("did:web:" + rest)
    return web_url[: -len("did.json")] + "did.jsonl"


# --------------------------------------------------------------------------- #
# hashing / key primitives (all validated against the didwebvh-rs golden vectors)
# --------------------------------------------------------------------------- #

def _jcs(obj: Any) -> bytes:
    try:
        return canonicalize(obj)
    except (JcsError, RecursionError, ValueError, TypeError) as exc:
        raise DidWebvhError(f"log entry is not JCS-canonicalizable: {exc}") from exc


def _multihash_b58(data: bytes) -> str:
    """``base58btc(0x12 0x20 ‖ sha256(data))`` — the did:webvh SCID / entryHash hash."""
    return b58btc_encode(_MULTIHASH_SHA256_PREFIX + hashlib.sha256(data).digest())


def _deep_replace_scid(obj: Any, scid: str) -> Any:
    """Replace every occurrence of *scid* with the ``{SCID}`` placeholder in all string
    values — the genesis entry carries the SCID in ``parameters.scid`` AND inside the DID
    string in ``state`` (id/controller/verificationMethod ids)."""
    if isinstance(obj, str):
        return obj.replace(scid, _SCID_PLACEHOLDER)
    if isinstance(obj, list):
        return [_deep_replace_scid(x, scid) for x in obj]
    if isinstance(obj, dict):
        return {k: _deep_replace_scid(v, scid) for k, v in obj.items()}
    return obj


def _prerotation_hash(multikey: str) -> str:
    """The pre-rotation commitment hash of an updateKey — ``base58btc(multihash-sha256(
    utf8(multikey)))`` over the multikey STRING (not its JCS form)."""
    return _multihash_b58(multikey.encode("utf-8"))


def _multikey_to_jwk(multikey: str) -> dict[str, Any]:
    """Decode an Ed25519 ``z6Mk…`` multikey to an OKP JWK, fail-closed. did:webvh v1.0
    ``updateKeys`` are Ed25519 (the ``eddsa-jcs-2022`` proof suite)."""
    try:
        raw = decode_multibase(multikey)
        code, off = read_varint(raw)
    except MultibaseError as exc:
        raise DidWebvhError(f"invalid updateKey multikey {multikey!r}: {exc}") from exc
    key = raw[off:]
    if code != _ED25519_MULTICODEC or len(key) != 32:
        raise DidWebvhError(
            f"updateKey {multikey!r} is not an Ed25519 multikey "
            f"(codec 0x{code:x}, {len(key)} bytes)")
    return {"kty": "OKP", "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")}


def _entry_without_proof(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k != "proof"}


# --------------------------------------------------------------------------- #
# per-entry verification
# --------------------------------------------------------------------------- #

def _verify_entry_proof(entry: dict[str, Any], active_keys: list[str]) -> None:
    """Verify the entry's ``eddsa-jcs-2022`` Data Integrity proof by a key in
    *active_keys*. hashData = ``sha256(JCS(proofConfig)) ‖ sha256(JCS(entry−proof))`` —
    the same shape as the JCS DI suites, over the log entry as the document."""
    from ..keys import verify_signature      # local: keeps did<-keys import lazy

    proofs = entry.get("proof")
    if isinstance(proofs, dict):              # tolerate a single proof object
        proofs = [proofs]
    if not isinstance(proofs, list) or not proofs:
        raise DidWebvhError("log entry has no proof")

    active = set(active_keys)
    document = _entry_without_proof(entry)
    doc_hash = hashlib.sha256(_jcs(document)).digest()

    for proof in proofs:
        if not isinstance(proof, dict):
            continue
        if proof.get("type") != "DataIntegrityProof" or proof.get("cryptosuite") != _EDDSA_JCS:
            continue
        if proof.get("proofPurpose") != "assertionMethod":
            continue
        vm = proof.get("verificationMethod")
        pv = proof.get("proofValue")
        if not isinstance(vm, str) or not isinstance(pv, str):
            continue
        # The verificationMethod names a key that MUST appear verbatim in active updateKeys.
        multikey = vm[len("did:key:"):].split("#", 1)[0] if vm.startswith("did:key:") else ""
        if multikey not in active:
            continue
        config = {k: v for k, v in proof.items() if k != "proofValue"}
        hash_data = hashlib.sha256(_jcs(config)).digest() + doc_hash
        try:
            sig = decode_multibase(pv)
        except MultibaseError:
            continue
        if verify_signature(alg="EdDSA", public_jwk=_multikey_to_jwk(multikey),
                            signing_input=hash_data, signature=sig):
            return
    raise DidWebvhError(
        "no valid eddsa-jcs-2022 proof by an authorized updateKey on this log entry")


def _parse_version_id(version_id: Any, expected_number: int) -> str:
    """Split ``{n}-{entryHash}``, checking *n* == *expected_number*; return entryHash."""
    if not isinstance(version_id, str) or "-" not in version_id:
        raise DidWebvhError(f"malformed versionId {version_id!r}")
    number, _, entry_hash = version_id.partition("-")
    if number != str(expected_number) or not entry_hash:
        raise DidWebvhError(
            f"versionId {version_id!r} is not version {expected_number} of the log")
    return entry_hash


def _witness_policy_active(witness: Any) -> bool:
    """Whether *witness* declares a policy that requires witness co-signatures.

    A ``did:webvh`` witness parameter is ``{"threshold": N, "witnesses": [...]}``.
    openvc cannot verify witness attestations, so ANY active policy must fail closed
    (:meth:`resolve` refuses) rather than silently downgrade to the un-witnessed model.
    The type of *threshold* is irrelevant to whether a policy is declared — a float,
    a string, or an omitted threshold alongside a witnesses list all still bind — so
    this treats any non-empty ``witnesses`` list, or any ``threshold`` that is not an
    explicit zero/false disable, as an active policy.
    """
    if not isinstance(witness, dict) or not witness:
        return False
    witnesses = witness.get("witnesses")
    if isinstance(witnesses, list) and len(witnesses) > 0:
        return True
    threshold = witness.get("threshold")
    return threshold is not None and threshold != 0     # 0 / False disable; else it binds


def _version_time(entry: dict[str, Any]) -> datetime:
    raw = entry.get("versionTime")
    if not isinstance(raw, str):
        raise DidWebvhError("log entry has no versionTime")
    text = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DidWebvhError(f"invalid versionTime {raw!r}: {exc}") from exc
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# the resolver
# --------------------------------------------------------------------------- #

class _WebvhReplay:
    """Shared did:webvh log replay — the SCID / entryHash-chain / proof / pre-rotation
    verification both resolvers run once the ``did.jsonl`` text is fetched. The replay is
    pure compute, so only the fetch (sync vs async) differs between the two subclasses."""

    _did_to_url = staticmethod(_did_webvh_url)

    def supports(self, did: str) -> bool:
        return did.startswith("did:webvh:")

    def _replay(self, did: str, log: str) -> DidDocument:
        entries = self._parse_lines(log)

        scid: str | None = None
        prev_version_id: str | None = None
        prev_time: datetime | None = None
        active_keys: list[str] = []            # updateKeys in force, carried forward
        next_key_hashes: list[str] = []        # pre-rotation commitment in force
        witness: dict[str, Any] = {}           # witness policy in force, carried forward
        state: dict[str, Any] = {}
        deactivated = False

        for index, entry in enumerate(entries):
            number = index + 1
            params = entry.get("parameters")
            if not isinstance(params, dict):
                raise DidWebvhError(f"entry {number} has no parameters object")
            declared_keys = params.get("updateKeys")
            # updateKeys, when present, must be a list of multikey STRINGS — a non-string
            # element would otherwise crash _prerotation_hash with a bare AttributeError,
            # before the entryHash/proof checks (so with no valid signature required).
            if declared_keys is not None and (
                    not isinstance(declared_keys, list)
                    or not all(isinstance(k, str) for k in declared_keys)):
                raise DidWebvhError(
                    f"entry {number}: updateKeys must be a list of multikey strings")

            # -- authorized signing keys for THIS entry -------------------- #
            if index == 0:
                if params.get("method") != "did:webvh:1.0":
                    raise DidWebvhError(
                        f"unsupported did:webvh method {params.get('method')!r} "
                        "(need did:webvh:1.0)")
                scid = params.get("scid")
                if not isinstance(scid, str) or not scid:
                    raise DidWebvhError("genesis entry has no scid")
                if not isinstance(declared_keys, list) or not declared_keys:
                    raise DidWebvhError("genesis entry has no updateKeys")
                authorized = declared_keys
                predecessor = scid
            elif next_key_hashes:               # pre-rotation active (set by the previous entry)
                if not isinstance(declared_keys, list) or not declared_keys:
                    raise DidWebvhError(
                        f"entry {number}: pre-rotation is active but it declares no updateKeys")
                for key in declared_keys:
                    if _prerotation_hash(key) not in next_key_hashes:
                        raise DidWebvhError(
                            f"entry {number}: updateKey {key!r} is not a pre-rotated key "
                            f"(its hash is not in the previous nextKeyHashes)")
                authorized = declared_keys
                assert prev_version_id is not None
                predecessor = prev_version_id
            else:                               # no pre-rotation: signed by the keys in force
                authorized = active_keys
                assert prev_version_id is not None
                predecessor = prev_version_id

            # -- SCID (genesis) -------------------------------------------- #
            if index == 0:
                assert scid is not None
                prelim = _deep_replace_scid(
                    {**_entry_without_proof(entry), "versionId": _SCID_PLACEHOLDER}, scid)
                if _multihash_b58(_jcs(prelim)) != scid:
                    raise DidWebvhError("SCID does not match the genesis entry (forged inception)")

            # -- entryHash chain ------------------------------------------- #
            entry_hash = _parse_version_id(entry.get("versionId"), number)
            assert predecessor is not None
            rehashed = {**_entry_without_proof(entry), "versionId": predecessor}
            recomputed = _multihash_b58(_jcs(rehashed))
            if recomputed != entry_hash:
                raise DidWebvhError(
                    f"entry {number}: entryHash mismatch — the log entry has been tampered with")

            # -- versionTime (monotonic non-decreasing) -------------------- #
            vtime = _version_time(entry)
            if prev_time is not None and vtime < prev_time:
                raise DidWebvhError(f"entry {number}: versionTime goes backwards")

            # -- proof ----------------------------------------------------- #
            _verify_entry_proof(entry, authorized)

            # -- carry parameters forward ---------------------------------- #
            if isinstance(declared_keys, list):
                active_keys = declared_keys
            if "nextKeyHashes" in params:
                nkh = params.get("nextKeyHashes")
                next_key_hashes = nkh if isinstance(nkh, list) else []
            if "witness" in params:
                w = params.get("witness")
                witness = w if isinstance(w, dict) else {}
            if "deactivated" in params:
                deactivated = bool(params.get("deactivated"))

            # A declared witness policy requires threshold witness co-signatures on each
            # entry, so a compromised updateKey alone cannot push an accepted update. openvc
            # does not verify witness attestations (verify-side witnessing is unsupported),
            # so a log that mandates them fails CLOSED rather than silently downgrading to
            # the un-witnessed trust model.
            if _witness_policy_active(witness):
                raise DidWebvhError(
                    f"entry {number}: a witness policy ({witness!r}) is declared, but verify-side "
                    "witness verification is unsupported — refusing to downgrade trust")

            new_state = entry.get("state")
            if not isinstance(new_state, dict):
                raise DidWebvhError(f"entry {number} has no state (DID document)")
            state = new_state
            prev_version_id = entry["versionId"]
            prev_time = vtime

        if state.get("id") != did:
            raise DidWebvhError(f"resolved document id {state.get('id')!r} != requested {did!r}")
        if deactivated:
            # A deactivated DID resolves, but its keys must not be handed back for
            # verification — fail closed so a caller cannot trust a retired identity.
            raise DidWebvhError(f"did:webvh {did!r} is deactivated")
        return parse_did_document(state)

    def _parse_lines(self, log: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for line in log.splitlines():
            if not line.strip():
                continue
            if len(entries) >= _MAX_LOG_ENTRIES:
                raise DidWebvhError(f"did.jsonl exceeds {_MAX_LOG_ENTRIES} entries")
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError) as exc:
                raise DidWebvhError(f"did.jsonl line is not valid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                raise DidWebvhError("each did.jsonl line must be a JSON object")
            entries.append(obj)
        if not entries:
            raise DidWebvhError("did.jsonl is empty")
        return entries


class DidWebvhResolver(_WebvhReplay):
    """Resolve a ``did:webvh`` DID by fetching and **replaying** its ``did.jsonl`` log.

    Takes an injected text fetch (``Callable[[str], str]`` returning the raw ``did.jsonl``);
    pass :func:`openvc.fetch.https_text_fetch`, or use
    :func:`openvc.fetch.default_did_webvh_resolver`."""

    def __init__(self, fetch: TextFetch) -> None:
        self._fetch = fetch

    def resolve(self, did: str) -> DidDocument:
        return self._replay(did, self._fetch(_did_webvh_url(did)))


class AsyncDidWebvhResolver(_WebvhReplay):
    """The async counterpart of :class:`DidWebvhResolver` — awaits an injected async text
    fetch (pass :func:`openvc.fetch.https_text_fetch_async`, or use
    :func:`openvc.fetch.default_async_did_webvh_resolver`), then replays the log (pure
    compute). Identical history/proof/pre-rotation checks."""

    def __init__(self, fetch: AsyncTextFetch) -> None:
        self._fetch = fetch

    async def resolve(self, did: str) -> DidDocument:
        return self._replay(did, await self._fetch(_did_webvh_url(did)))


__all__ = [
    "AsyncDidWebvhResolver",
    "AsyncTextFetch",
    "DidWebvhError",
    "DidWebvhResolver",
    "TextFetch",
]
