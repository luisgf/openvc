"""
tests/test_type_metadata.py — SD-JWT VC Type Metadata verifier (#21).

Pins the draft-ietf-oauth-sd-jwt-vc-17 §4 processing to the draft's own Appendix B.2
worked example (the "Betelgeuse education credential" — Figure 28 payload + Figure 29
Type Metadata `claims`), the DCQL-style `path` engine (§4.6.1), and the fail-closed
guards: `vct#integrity` (W3C SRI over the raw bytes), the `vct` identity check, and the
`extends` chain (integrity per link + cycle/depth bound).

Note: the current draft REMOVED embedded JSON Schema (draft-12) — validation is via the
`claims` array. The draft's published example integrity hashes are not byte-reproducible
from the formatted JSON (SRI is over literal transferred bytes, with no canonicalization),
so integrity is pinned over a locally-serialized document, not the draft's printed hash.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from openvc.type_metadata import (
    TypeMetadataClaimsInvalid,
    TypeMetadataError,
    TypeMetadataMismatch,
    TypeMetadataResolutionError,
    _select,
    _validate_claims,
    validate_type_metadata,
)

VCT = "https://betelgeuse.example.com/education_credential/v42"
PARENT_VCT = "https://galaxy.example.com/galactic-education-credential/v2"

# Figure 28 — the processed SD-JWT VC payload the Type Metadata validates.
PAYLOAD = {
    "vct": VCT,
    "name": "Zaphod Beeblebrox",
    "address": {"street_address": "42 Galaxy Way", "city": "Betelgeuse City",
                "postal_code": "12345", "country": "Betelgeuse"},
    "degrees": [{"field_of_study": "Intergalactic Politics", "date_awarded": "2020-05-15"},
                {"field_of_study": "Space Navigation", "date_awarded": "2018-06-20"},
                {"field_of_study": "Quantum Mechanics", "date_awarded": "2016-07-25"}],
}

# Figure 29 — the `claims` metadata (paths + mandatory/sd), verbatim shape.
CLAIMS = [
    {"path": ["name"], "sd": "always", "mandatory": True},
    {"path": ["address"], "sd": "always"},
    {"path": ["address", "street_address"], "sd": "always", "svg_id": "address_street_address"},
    {"path": ["degrees"], "sd": "never"},
    {"path": ["degrees", None], "sd": "always"},
    {"path": ["degrees", None, "field_of_study"], "sd": "never"},
    {"path": ["degrees", None, "date_awarded"], "sd": "always"},
]


def _sri(data: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode()


def _store_resolver(store):
    def resolve(url):
        if url not in store:
            from openvc.errors import OpenvcError
            raise OpenvcError(f"no metadata at {url}")
        return store[url]
    return resolve


# --------------------------------------------------------------------------- #
# the draft-17 worked example
# --------------------------------------------------------------------------- #

def test_worked_example_claims_validate():
    _validate_claims(PAYLOAD, CLAIMS)                     # Figure 28 satisfies Figure 29


def test_full_resolution_with_integrity_and_extends():
    parent = {"vct": PARENT_VCT, "claims": CLAIMS[3:]}    # supertype supplies the degree claims
    parent_bytes = json.dumps(parent).encode()
    child = {"vct": VCT, "name": "Betelgeuse Education Credential", "extends": PARENT_VCT,
             "extends#integrity": _sri(parent_bytes), "claims": CLAIMS[:3]}
    child_bytes = json.dumps(child).encode()
    resolve = _store_resolver({VCT: child_bytes, PARENT_VCT: parent_bytes})

    result = validate_type_metadata(
        PAYLOAD, vct=VCT, vct_integrity=_sri(child_bytes), resolve=resolve)
    assert result.vct == VCT
    assert len(result.documents) == 2                     # child + parent
    assert len(result.claims) == 7                        # composed


def test_child_claim_overrides_parent_by_path():
    parent = {"vct": PARENT_VCT, "claims": [{"path": ["name"], "mandatory": False}]}
    child = {"vct": VCT, "extends": PARENT_VCT, "claims": [{"path": ["name"], "mandatory": True}]}
    store = {VCT: json.dumps(child).encode(), PARENT_VCT: json.dumps(parent).encode()}
    result = validate_type_metadata(PAYLOAD, vct=VCT, resolve=_store_resolver(store))
    name_claims = [c for c in result.claims if c["path"] == ["name"]]
    assert len(name_claims) == 1 and name_claims[0]["mandatory"] is True   # child wins


# --------------------------------------------------------------------------- #
# the DCQL-style path engine (§4.6.1)
# --------------------------------------------------------------------------- #

def test_path_engine_selects():
    assert _select(PAYLOAD, ["name"]) == ["Zaphod Beeblebrox"]
    assert _select(PAYLOAD, ["address", "street_address"]) == ["42 Galaxy Way"]
    assert _select(PAYLOAD, ["degrees", None, "field_of_study"]) == [
        "Intergalactic Politics", "Space Navigation", "Quantum Mechanics"]
    assert _select(PAYLOAD, ["degrees", 1, "date_awarded"]) == ["2018-06-20"]
    assert _select(PAYLOAD, ["missing_key"]) == []        # missing key -> dropped
    assert _select(PAYLOAD, ["degrees", 9]) == []         # out-of-range index -> dropped


@pytest.mark.parametrize("path", [
    ["name", "sub"],            # string component on a non-object
    ["name", None],             # null component on a non-array
    ["address", 0],             # index component on a non-array
    ["degrees", "field"],       # string component on an array
    ["degrees", 0, "field_of_study", 0],  # index on a scalar leaf
    ["degrees", -1],            # negative index is invalid
    ["degrees", True],          # bool is not a valid component
], ids=["str-on-scalar", "null-on-scalar", "idx-on-object", "str-on-array",
        "idx-on-scalar", "negative-idx", "bool-component"])
def test_path_structural_errors_are_rejected(path):
    with pytest.raises(TypeMetadataClaimsInvalid):
        _select(PAYLOAD, path)


# --------------------------------------------------------------------------- #
# fail-closed guards
# --------------------------------------------------------------------------- #

def test_mandatory_claim_absent_is_rejected():
    with pytest.raises(TypeMetadataClaimsInvalid):
        _validate_claims({"address": {}}, CLAIMS)         # no "name"


def test_empty_path_is_rejected():
    with pytest.raises(TypeMetadataClaimsInvalid):
        _validate_claims(PAYLOAD, [{"path": []}])


def test_vct_integrity_mismatch_is_rejected():
    doc = json.dumps({"vct": VCT}).encode()
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata(
            PAYLOAD, vct=VCT, vct_integrity=_sri(b"different bytes"),
            resolve=_store_resolver({VCT: doc}))


def test_vct_mismatch_is_rejected():
    doc = json.dumps({"vct": "https://evil.example/other"}).encode()
    with pytest.raises(TypeMetadataMismatch):
        validate_type_metadata(PAYLOAD, vct=VCT, resolve=_store_resolver({VCT: doc}))


def test_extends_cycle_is_rejected():
    doc = json.dumps({"vct": VCT, "extends": VCT}).encode()
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata(PAYLOAD, vct=VCT, resolve=_store_resolver({VCT: doc}))


def test_extends_depth_is_bounded():
    # a chain longer than max_extends_depth is rejected before exhausting resolution
    store, prev = {}, None
    for i in range(20):
        this = f"https://ex/type/{i}"
        doc = {"vct": this}
        if prev is not None:
            doc["extends"] = prev
        store[this] = json.dumps(doc).encode()
        prev = this
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata({}, vct="https://ex/type/19",
                               resolve=_store_resolver(store), max_extends_depth=5)


def test_resolver_error_fails_closed():
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata(PAYLOAD, vct=VCT, resolve=_store_resolver({}))   # not found


@pytest.mark.parametrize("raw", [b"{not json", json.dumps([1, 2]).encode(),
                                 json.dumps("a string").encode()],
                         ids=["bad-json", "json-array", "json-string"])
def test_non_object_metadata_is_rejected(raw):
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata(PAYLOAD, vct=VCT, resolve=_store_resolver({VCT: raw}))


def test_non_bytes_resolver_return_is_rejected():
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata(PAYLOAD, vct=VCT, resolve=lambda url: {"vct": VCT})


# --------------------------------------------------------------------------- #
# regressions from the adversarial review
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_path", [["address", ["street"]], {"weird": 1}, "not-a-list", 5],
                         ids=["nested-list", "dict", "string", "int"])
def test_malformed_claim_path_fails_closed(bad_path):
    # a malformed (e.g. unhashable) path in an inherited claim must fail closed as a
    # typed error, not a bare TypeError from _compose_claims' set keying
    parent = {"vct": PARENT_VCT, "claims": [{"path": bad_path}]}
    child = {"vct": VCT, "extends": PARENT_VCT}
    store = {VCT: json.dumps(child).encode(), PARENT_VCT: json.dumps(parent).encode()}
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata({}, vct=VCT, resolve=_store_resolver(store))


@pytest.mark.parametrize("boom", [ValueError("x"), KeyError("k"), RuntimeError("r")],
                         ids=["value", "key", "runtime"])
def test_custom_resolver_exception_is_wrapped(boom):
    def resolve(url):
        raise boom
    with pytest.raises(TypeMetadataResolutionError):
        validate_type_metadata({}, vct=VCT, resolve=resolve)


def test_path_selection_is_node_bounded():
    # a null-heavy path over a deeply-nested payload must not blow up combinatorially
    def nested(width, depth):
        return [nested(width, depth - 1) for _ in range(width)] if depth else 0
    with pytest.raises(TypeMetadataClaimsInvalid):
        _select({"root": nested(8, 8)}, ["root"] + [None] * 8)


def test_errors_share_one_base():
    for exc in (TypeMetadataResolutionError, TypeMetadataMismatch, TypeMetadataClaimsInvalid):
        assert issubclass(exc, TypeMetadataError)


def test_default_resolver_fetches_bytes():
    from openvc.resolvers import default_type_metadata_resolver
    calls = {}

    def fake_fetch(url):
        calls["url"] = url
        return b'{"vct": "x"}'

    resolve = default_type_metadata_resolver(fetch=fake_fetch)
    assert resolve("https://issuer.example/type") == b'{"vct": "x"}'
    assert calls["url"] == "https://issuer.example/type"
