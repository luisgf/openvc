"""
tests/test_status_index_hostile.py — a hostile status-list index is a typed error.

``verify_many`` / ``verify_many_async`` catch only ``OpenvcError`` per item (#99), so a
bare exception from any parser aborts the WHOLE batch. ``parse_status_entries`` read
``statusListIndex`` with ``int(index)`` and caught ``TypeError``/``ValueError`` but not
``OverflowError``: a signed VC-JWT whose index was ``Infinity`` / ``1e400`` escaped as
``OverflowError: cannot convert float infinity to integer``. It did so even under
``require_status=False``, because the entries are parsed before the resolver check —
and a self-issued ``did:jwk`` is enough to mint one. The same ``int()`` read a bool as
bit 1, ``3.7`` as bit 3, and ``" 5"`` / ``"+5"`` / ``"5_0"`` / ``"٥"`` as bit 5 or 50.

Both status conventions now share one index rule (``openvc.status._index``): the W3C
``statusListIndex`` and the IETF ``status.status_list.idx``. Each hostile index is
driven through the single verify AND a ``[good, bad, good]`` batch — sync and async,
``require_status`` True and False — and the good neighbours must still verify.

The tokens are signed over literal payload TEXT, so ``Infinity``, ``NaN`` and ``1e400``
reach ``json.loads`` exactly as an attacker would send them. Helpers are self-contained
(tests/ is not a package — no cross-import).
"""
from __future__ import annotations

import asyncio
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openvc import (
    VerificationPolicy,
    verify_credential,
    verify_credential_async,
    verify_many,
    verify_many_async,
)
from openvc.errors import OpenvcError
from openvc.keys import P256SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import (
    CredentialRevoked,
    StatusListError,
    encode_bitstring,
    parse_status_entries,
    parse_token_status_ref,
)
from openvc.status._index import MAX_STATUS_INDEX
from openvc.status.token_status_list import encode_status_list

LIST_URL = "https://status.example/w3c/1"
TOKEN_URI = "https://status.example/ietf/1"
SENTINEL = "__HOSTILE_INDEX__"


# --------------------------------------------------------------------------- #
# helpers (self-contained)
# --------------------------------------------------------------------------- #

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _self_issued_did_jwk() -> tuple[P256SigningKey, str]:
    """A fresh P-256 key and the did:jwk it self-issues as — no trust needed."""
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = P256SigningKey(priv, kid="tmp").public_jwk()
    did = "did:jwk:" + _b64url(json.dumps(jwk, separators=(",", ":")).encode())
    return P256SigningKey(priv, kid=f"{did}#0"), did


KEY, DID = _self_issued_did_jwk()


def _resign_with_literal(token: str, literal: str | None) -> str:
    """Swap the quoted SENTINEL in the issuer JWT's payload for *literal* — raw JSON
    text such as ``Infinity`` or ``1e400`` — and re-sign it with the issuer key. An
    SD-JWT's ``~`` tail rides along untouched. ``None`` keeps the token as issued."""
    if literal is None:
        return token
    jws, sep, tail = token.partition("~")
    header_b64, payload_b64, _ = jws.split(".")
    text = _b64url_decode(payload_b64).decode("utf-8")
    assert f'"{SENTINEL}"' in text
    payload_b64 = _b64url(text.replace(f'"{SENTINEL}"', literal).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature = KEY.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{_b64url(signature)}{sep}{tail}"


def _w3c_vc_jwt(index_literal: str | None, entry_type: str = "BitstringStatusListEntry") -> str:
    """A VC-JWT whose ``vc.credentialStatus.statusListIndex`` is *index_literal* (raw
    JSON text); ``None`` gives a well-formed index ``"3"`` (bit clear)."""
    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "credentialSubject": {"id": "did:example:alice"},
        "credentialStatus": {
            "type": entry_type,
            "statusPurpose": "revocation",
            "statusListIndex": SENTINEL if index_literal is not None else "3",
            "statusListCredential": LIST_URL,
        },
    }
    return _resign_with_literal(
        VcJwtProofSuite().sign(credential, signing_key=KEY), index_literal)


def _ietf_sd_jwt_vc(idx_literal: str | None) -> str:
    """An SD-JWT VC whose ``status.status_list.idx`` is *idx_literal* (raw JSON text);
    ``None`` gives a well-formed ``idx`` of 3 (VALID)."""
    claims = {
        "iss": DID,
        "sub": "did:example:alice",
        "status": {"status_list": {
            "idx": SENTINEL if idx_literal is not None else 3, "uri": TOKEN_URI}},
    }
    sd_jwt = SdJwtVcProofSuite().issue(
        claims, signing_key=KEY, vct="https://credentials.example/identity")
    return _resign_with_literal(sd_jwt, idx_literal)


def _ietf_vc_jwt(idx_literal: str | None) -> str:
    """A VC-JWT carrying an IETF ``status`` claim in its JWT payload (the pipeline
    checks both conventions on every format) with ``idx`` = *idx_literal*."""
    token = VcJwtProofSuite().sign({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "credentialSubject": {"id": "did:example:alice"},
    }, signing_key=KEY)
    header_b64, payload_b64, _ = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64))
    payload["status"] = {"status_list": {
        "idx": SENTINEL if idx_literal is not None else 3, "uri": TOKEN_URI}}
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    rebuilt = f"{signing_input}.{_b64url(KEY.sign(signing_input.encode('ascii')))}"
    return _resign_with_literal(rebuilt, idx_literal)


W3C_LIST = {
    "type": ["VerifiableCredential", "BitstringStatusListCredential"],
    "credentialSubject": {"statusPurpose": "revocation",
                          "encodedList": encode_bitstring(bytes(32))},
}
IETF_LIST = {"sub": TOKEN_URI,
             "status_list": {"bits": 1, "lst": encode_status_list(bytes(32))}}


class _Fetches:
    """Status resolvers (sync and async) that record every URL they are asked for."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def w3c(self, url: str) -> dict:
        self.urls.append(url)
        return W3C_LIST

    def ietf(self, uri: str) -> dict:
        self.urls.append(uri)
        return IETF_LIST

    async def w3c_async(self, url: str) -> dict:
        return self.w3c(url)

    async def ietf_async(self, uri: str) -> dict:
        return self.ietf(uri)


def _kwargs(fetches: _Fetches, require_status: bool, *, is_async: bool) -> dict:
    """``require_status=True`` gets real resolvers (the hostile index must fail before
    any fetch); ``False`` gets none, the opt-out the bug also escaped through."""
    kw: dict = {"policy": VerificationPolicy(require_status=require_status)}
    if require_status:
        kw["resolve_status_list"] = fetches.w3c_async if is_async else fetches.w3c
        kw["resolve_status_list_token"] = fetches.ietf_async if is_async else fetches.ietf
    return kw


def _outcomes(results) -> list[str]:
    return ["ok" if r.ok else type(r.error).__name__ for r in results]


BIGNUM = "1" + "0" * 400                 # an integer no float holds


# Raw JSON text for a W3C statusListIndex. The REC makes it a base-10 string; a JSON
# integer stays tolerated, so only the out-of-range integers are hostile here.
HOSTILE_W3C_INDEX = {
    "Infinity": "Infinity",              # the reported OverflowError
    "-Infinity": "-Infinity",
    "1e400": "1e400",                    # json.loads -> inf, same escape
    "-1e400": "-1e400",
    "NaN": "NaN",
    "true": "true",                      # int(True) == 1: read as bit 1
    "false": "false",
    "fraction": "3.7",                   # int(3.7) == 3: silently truncated
    "integral-float": "5.0",
    "bignum": BIGNUM,
    "negative-bignum": "-" + BIGNUM,
    "negative": "-1",
    "past-max": str(MAX_STATUS_INDEX),
    "str-bignum": json.dumps(BIGNUM),
    "str-past-max": json.dumps(str(MAX_STATUS_INDEX)),
    "str-negative": '"-1"',
    "str-plus": '"+5"',                  # int("+5") == 5
    "str-space": '" 5"',                 # int(" 5") == 5
    "str-underscore": '"5_0"',           # int("5_0") == 50
    "str-arabic-indic": '"\\u0665"',     # int("٥") == 5
    "str-exponent": '"1e400"',
    "str-infinity": '"Infinity"',
    "str-empty": '""',
    "array": "[3]",
    "object": '{"value": 3}',
}

# Raw JSON text for an IETF status_list idx — the draft makes it a JSON integer.
HOSTILE_IETF_IDX = {
    "Infinity": "Infinity",
    "-Infinity": "-Infinity",
    "1e400": "1e400",
    "-1e400": "-1e400",
    "NaN": "NaN",
    "true": "true",
    "false": "false",
    "fraction": "3.7",
    "integral-float": "5.0",
    "bignum": BIGNUM,
    "negative-bignum": "-" + BIGNUM,
    "negative": "-1",
    "past-max": str(MAX_STATUS_INDEX),
    "string": '"3"',
    "array": "[3]",
}

MINTERS = {
    "w3c-vcjwt": (_w3c_vc_jwt, HOSTILE_W3C_INDEX),
    "ietf-sdjwtvc": (_ietf_sd_jwt_vc, HOSTILE_IETF_IDX),
    "ietf-vcjwt": (_ietf_vc_jwt, HOSTILE_IETF_IDX),
}

CASES = [
    pytest.param(lane, literal, id=f"{lane}-{name}")
    for lane, (_, table) in MINTERS.items()
    for name, literal in table.items()
]


# --------------------------------------------------------------------------- #
# end to end — single verify and batch, sync and async, require_status on/off
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("require_status", [True, False], ids=["require", "opt-out"])
@pytest.mark.parametrize("lane, literal", CASES)
def test_hostile_index_fails_typed_in_single_verify(lane, literal, require_status):
    mint, _ = MINTERS[lane]
    bad = mint(literal)
    fetches = _Fetches()
    with pytest.raises(StatusListError):
        verify_credential(bad, **_kwargs(fetches, require_status, is_async=False))
    with pytest.raises(StatusListError):
        asyncio.run(verify_credential_async(
            bad, **_kwargs(fetches, require_status, is_async=True)))
    assert fetches.urls == []            # refused at parse, before any status fetch


@pytest.mark.parametrize("require_status", [True, False], ids=["require", "opt-out"])
@pytest.mark.parametrize("lane, literal", CASES)
def test_hostile_index_never_aborts_the_batch(lane, literal, require_status):
    mint, _ = MINTERS[lane]
    good, bad = mint(None), mint(literal)
    batch = [good, bad, good]
    fetches = _Fetches()

    results = verify_many(batch, **_kwargs(fetches, require_status, is_async=False))
    assert _outcomes(results) == ["ok", "StatusListError", "ok"]
    assert [r.index for r in results] == [0, 1, 2]

    async_results = asyncio.run(verify_many_async(
        batch, **_kwargs(fetches, require_status, is_async=True)))
    assert _outcomes(async_results) == ["ok", "StatusListError", "ok"]

    if require_status:                   # the good items really were status-checked
        assert all(r.result.status is not None and not r.result.status.revoked
                   for r in (results[0], results[2], async_results[0], async_results[2]))


def test_statuslist2021_entry_takes_the_same_rule():
    """The older StatusList2021Entry shares the parser — same escape, same fix."""
    bad = _w3c_vc_jwt("Infinity", entry_type="StatusList2021Entry")
    good = _w3c_vc_jwt(None, entry_type="StatusList2021Entry")
    results = verify_many([good, bad, good], policy=VerificationPolicy(require_status=False))
    assert _outcomes(results) == ["ok", "StatusListError", "ok"]


# --------------------------------------------------------------------------- #
# the parsers directly — what is still accepted, and the error messages
# --------------------------------------------------------------------------- #

def _w3c_entry(index) -> dict:
    return {"credentialStatus": {
        "type": "BitstringStatusListEntry", "statusPurpose": "revocation",
        "statusListIndex": index, "statusListCredential": LIST_URL}}


def _ietf_ref(idx) -> dict:
    return {"status": {"status_list": {"idx": idx, "uri": TOKEN_URI}}}


@pytest.mark.parametrize("index, expected", [
    ("0", 0),
    ("42", 42),
    ("007", 7),                                       # leading zeros are still base 10
    ("0" * 50 + "9", 9),                              # ...however many
    (str(MAX_STATUS_INDEX - 1), MAX_STATUS_INDEX - 1),
    (42, 42),                                         # a JSON integer stays tolerated
    (MAX_STATUS_INDEX - 1, MAX_STATUS_INDEX - 1),
])
def test_w3c_well_formed_indices_still_parse(index, expected):
    [entry] = parse_status_entries(_w3c_entry(index))
    assert entry.index == expected and type(entry.index) is int


@pytest.mark.parametrize("idx", [0, 42, MAX_STATUS_INDEX - 1])
def test_ietf_well_formed_idx_still_parses(idx):
    ref = parse_token_status_ref(_ietf_ref(idx))
    assert ref is not None and ref.index == idx


@pytest.mark.parametrize("value", [
    float("inf"), float("-inf"), float("nan"), True, False, 3.7, 5.0,
    10 ** 400, -(10 ** 400), MAX_STATUS_INDEX, -1,
], ids=["inf", "-inf", "nan", "true", "false", "fraction", "integral-float",
        "bignum", "negative-bignum", "past-max", "negative"])
@pytest.mark.parametrize("parse", [
    lambda v: parse_status_entries(_w3c_entry(v)),
    lambda v: parse_token_status_ref(_ietf_ref(v)),
], ids=["w3c", "ietf"])
def test_parsers_reject_hostile_python_values(parse, value):
    with pytest.raises(StatusListError):
        parse(value)


def test_error_message_survives_an_int_past_the_str_digit_limit():
    """An int past ``sys.get_int_max_str_digits`` (4300) cannot come from JSON, but a
    caller can hand one in: rendering it with repr() would raise a bare ValueError.
    The message names its size instead."""
    huge = 10 ** 5000
    for parse in (lambda: parse_status_entries(_w3c_entry(huge)),
                  lambda: parse_token_status_ref(_ietf_ref(huge)),
                  lambda: parse_token_status_ref(_ietf_ref(-huge))):
        with pytest.raises(StatusListError, match="-bit integer"):
            parse()


def test_error_message_does_not_repr_a_deeply_nested_index():
    """repr() of a deeply nested list overflows the stack (bare RecursionError); the
    message names the type instead."""
    deep: list = []
    for _ in range(100_000):
        deep = [deep]
    with pytest.raises(StatusListError, match="got a list"):
        parse_status_entries(_w3c_entry(deep))
    with pytest.raises(StatusListError, match="got a list"):
        parse_token_status_ref(_ietf_ref(deep))


def test_error_message_truncates_a_long_string_index():
    with pytest.raises(StatusListError) as info:
        parse_status_entries(_w3c_entry("9" * 100_000))
    assert len(str(info.value)) < 200


# --------------------------------------------------------------------------- #
# the rest of the status path — found by this change's adversarial review
# --------------------------------------------------------------------------- #
# The same parsers still str()'d or repr()'d other attacker values. On Python 3.14,
# json.loads accepts arrays nested deeper than str()/repr() can render (~70k-115k
# levels), so a deep array there was a bare RecursionError: the same batch abort.
# Older Pythons refuse that JSON up front (a typed MalformedToken), so the end-to-end
# tests assert "typed, neighbours fine" and the parser-level tests pin the rule itself
# with a Python-built deep list, on every version.

DEEP_JSON = "[" * 90_000 + "]" * 90_000


def _deep_list(depth: int = 100_000) -> list:
    deep: list = []
    for _ in range(depth):
        deep = [deep]
    return deep


def _signed_jwt(header: dict, payload: dict, literals: dict[str, str]) -> str:
    """Sign *payload* with KEY after swapping each quoted sentinel key of *literals* in
    its JSON text for the raw JSON text it maps to."""
    text = json.dumps(payload, separators=(",", ":"))
    for sentinel, literal in literals.items():
        assert f'"{sentinel}"' in text
        text = text.replace(f'"{sentinel}"', literal)
    signing_input = (f"{_b64url(json.dumps(header).encode())}."
                     f"{_b64url(text.encode('utf-8'))}")
    return f"{signing_input}.{_b64url(KEY.sign(signing_input.encode('ascii')))}"


def _vc_jwt_payload(credential_status=None, status=None, vc_id=None) -> dict:
    vc: dict = {"@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"], "issuer": DID,
                "credentialSubject": {"id": "did:example:alice"}}
    if vc_id is not None:
        vc["id"] = vc_id                  # no jti: PyJWT would type-check that first
    if credential_status is not None:
        vc["credentialStatus"] = credential_status
    payload: dict = {"iss": DID, "iat": 1_700_000_000, "vc": vc}
    if status is not None:
        payload["status"] = status
    return payload


VC_JWT_HEADER = {"alg": "ES256", "typ": "JWT", "kid": f"{DID}#0"}


def _assert_only_the_middle_item_failed_typed(results) -> None:
    assert [r.ok for r in results] == [True, False, True]
    assert isinstance(results[1].error, OpenvcError)


@pytest.mark.parametrize("credential_status, status", [
    ({"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
      "statusListIndex": "3", "statusListCredential": "S"}, None),
    (None, {"status_list": {"idx": 3, "uri": "S"}}),
], ids=["w3c-statusListCredential", "ietf-uri"])
@pytest.mark.parametrize("require_status", [True, False], ids=["require", "opt-out"])
def test_deep_status_url_never_aborts_the_batch(credential_status, status, require_status):
    bad = _signed_jwt(VC_JWT_HEADER, _vc_jwt_payload(credential_status, status),
                      {"S": DEEP_JSON})
    good = _w3c_vc_jwt(None)
    fetches = _Fetches()
    _assert_only_the_middle_item_failed_typed(
        verify_many([good, bad, good], **_kwargs(fetches, require_status, is_async=False)))
    _assert_only_the_middle_item_failed_typed(asyncio.run(verify_many_async(
        [good, bad, good], **_kwargs(fetches, require_status, is_async=True))))


def test_revoked_credential_with_a_deep_id_never_aborts_the_batch():
    """The pipeline's "credential … is revoked" message repr()'d ``vc.id``; the issuer
    of a self-issued credential controls both that id and its own list's bit."""
    revoked_list = {
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "credentialSubject": {"statusPurpose": "revocation",
                              "encodedList": encode_bitstring(b"\x04" + bytes(31))},
    }                                                     # bit 5 set, bit 3 clear
    bad = _signed_jwt(VC_JWT_HEADER, _vc_jwt_payload(
        {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
         "statusListIndex": "5", "statusListCredential": LIST_URL}, vc_id="ID"),
        {"ID": DEEP_JSON})
    good = _w3c_vc_jwt(None)

    async def resolve_async(url):
        return revoked_list

    _assert_only_the_middle_item_failed_typed(verify_many(
        [good, bad, good], resolve_status_list=lambda url: revoked_list))
    _assert_only_the_middle_item_failed_typed(asyncio.run(verify_many_async(
        [good, bad, good], resolve_status_list=resolve_async)))


def test_revoked_message_does_not_repr_a_container_id():
    revoked_list = {"credentialSubject": {"encodedList": encode_bitstring(b"\x04" + bytes(31))}}
    bad = _signed_jwt(VC_JWT_HEADER, _vc_jwt_payload(
        {"type": "BitstringStatusListEntry", "statusListIndex": "5",
         "statusListCredential": LIST_URL}, vc_id="ID"), {"ID": '{"nested": [1]}'})
    with pytest.raises(CredentialRevoked, match="credential None is revoked"):
        verify_credential(bad, resolve_status_list=lambda url: revoked_list)


@pytest.mark.parametrize("field, value", [
    ("statusListCredential", "deep"),
    ("statusListCredential", 5),
    ("statusListCredential", {"id": LIST_URL}),
    ("statusListCredential", [LIST_URL]),
    ("statusPurpose", "deep"),
    ("statusPurpose", None),             # an explicit null matched no purpose: bit ignored
    ("statusPurpose", 5),
    ("statusPurpose", ["revocation"]),
])
def test_w3c_entry_rejects_non_string_url_and_purpose(field, value):
    raw = _w3c_entry("3")
    raw["credentialStatus"][field] = _deep_list() if value == "deep" else value
    with pytest.raises(StatusListError, match=f"{field} must be"):
        parse_status_entries(raw)


@pytest.mark.parametrize("value", ["deep", 5, {"href": TOKEN_URI}, [TOKEN_URI]])
def test_ietf_ref_rejects_a_non_string_uri(value):
    ref = _ietf_ref(3)
    ref["status"]["status_list"]["uri"] = _deep_list() if value == "deep" else value
    with pytest.raises(StatusListError, match="uri must be a URL string"):
        parse_token_status_ref(ref)


def _corrupt_deflate_list() -> str:
    """A valid gzip header over an invalid DEFLATE block: GzipFile raises zlib.error."""
    body = bytes.fromhex("1f8b0800000000000000ff") + b"\xff" * 8
    return "u" + _b64url(body)


@pytest.mark.parametrize("resolved", [
    None, [], "a string", "deep",
    {"credentialSubject": {"statusPurpose": "deep", "encodedList": "x"}},
    {"credentialSubject": {"encodedList": "deep"}},
    {"credentialSubject": {"encodedList": 5}},
    {"credentialSubject": {"encodedList": "corrupt-deflate"}},
], ids=["none", "list", "str", "deep", "deep-purpose", "deep-encodedList",
        "int-encodedList", "corrupt-deflate"])
def test_w3c_resolved_list_shapes_fail_typed(resolved):
    from openvc.status import check_credential_status

    if resolved == "deep":
        resolved = _deep_list()
    elif isinstance(resolved, dict):
        subject = dict(resolved["credentialSubject"])
        for key, value in subject.items():
            if value == "deep":
                subject[key] = _deep_list()
            elif value == "corrupt-deflate":
                subject[key] = _corrupt_deflate_list()
        resolved = {"credentialSubject": subject}
    with pytest.raises(StatusListError):
        check_credential_status(_w3c_entry("3"), resolve_status_list=lambda url: resolved)


def test_corrupt_deflate_list_never_aborts_the_batch():
    """The issuer serves its own list; verify_many fetches each list URL once."""
    corrupt_url = "https://status.example/w3c/corrupt"
    corrupt = {"credentialSubject": {"statusPurpose": "revocation",
                                     "encodedList": _corrupt_deflate_list()}}
    bad = _signed_jwt(VC_JWT_HEADER, _vc_jwt_payload(
        {"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
         "statusListIndex": "3", "statusListCredential": corrupt_url}), {})
    good = _w3c_vc_jwt(None)

    def resolve(url):
        return corrupt if url == corrupt_url else W3C_LIST

    async def resolve_async(url):
        return resolve(url)

    assert _outcomes(verify_many([good, bad, good], resolve_status_list=resolve)) == [
        "ok", "StatusListError", "ok"]
    assert _outcomes(asyncio.run(verify_many_async(
        [good, bad, good], resolve_status_list=resolve_async))) == [
        "ok", "StatusListError", "ok"]


@pytest.mark.parametrize("resolved", [
    None, [], "a string", "deep",
    {"status_list": {"bits": "deep", "lst": encode_status_list(bytes(4))}},
    {"status_list": {"bits": 1.0, "lst": encode_status_list(bytes(4))}},
    {"status_list": {"bits": 1, "lst": "deep"}},
], ids=["none", "list", "str", "deep", "deep-bits", "float-bits", "deep-lst"])
def test_ietf_resolved_token_shapes_fail_typed(resolved):
    from openvc.status import check_token_status

    if resolved == "deep":
        resolved = _deep_list()
    elif isinstance(resolved, dict):
        sl = {k: (_deep_list() if v == "deep" else v)
              for k, v in resolved["status_list"].items()}
        resolved = {"status_list": sl}
    with pytest.raises(StatusListError):
        check_token_status(_ietf_ref(3), resolve_status_list_token=lambda uri: resolved)


# -- verify_status_list_token (what the blessed IETF resolver runs) ----------- #

STATUS_TOKEN_HEADER = {"typ": "statuslist+jwt", "alg": "ES256", "kid": f"{DID}#0"}


def _status_list_token(literals: dict[str, str], **claims) -> str:
    payload = {"sub": TOKEN_URI, "iat": 1_700_000_000,
               "status_list": {"bits": 1, "lst": encode_status_list(bytes(4))}}
    payload.update(claims)
    return _signed_jwt(STATUS_TOKEN_HEADER, payload, literals)


def _verify_status_token(token: str) -> dict:
    from openvc.status.issue import verify_status_list_token
    return verify_status_list_token(
        token, public_key_jwk=KEY.public_jwk(), expected_uri=TOKEN_URI)


def test_status_list_token_control_verifies():
    assert _verify_status_token(_status_list_token({}))["sub"] == TOKEN_URI


@pytest.mark.parametrize("literal", [
    "NaN", "Infinity", "-Infinity", "1e400", "true", '"2030-01-01"', BIGNUM, "[1]",
    DEEP_JSON,
], ids=["NaN", "Infinity", "-Infinity", "1e400", "true", "string", "bignum", "array",
        "deep"])
def test_status_list_token_exp_must_be_a_finite_number(literal):
    """NaN / ±Infinity compare False against every clock: the list would never expire."""
    with pytest.raises(OpenvcError):
        _verify_status_token(_status_list_token({"EXP": literal}, exp="EXP"))


def test_status_list_token_with_a_deep_sub_fails_typed():
    with pytest.raises(OpenvcError):
        _verify_status_token(_status_list_token({"SUB": DEEP_JSON}, sub="SUB"))


def test_status_list_token_messages_do_not_repr_containers():
    """Python-built shapes pin the message rule on every version (no JSON depth cap)."""
    from openvc.status.issue import verify_status_list_token
    import openvc.status.issue as issue_mod

    deep = _deep_list()
    for header, claims, match in [
        ({"typ": deep}, {}, "unexpected token typ a list"),
        ({"typ": "statuslist+jwt"}, {"sub": deep}, "sub a list"),
        ({"typ": "statuslist+jwt"}, {"sub": TOKEN_URI, "exp": deep}, "got a list"),
    ]:
        original = issue_mod.verify_compact
        issue_mod.verify_compact = lambda token, public_key_jwk, h=header, c=claims: (h, c)
        try:
            with pytest.raises(StatusListError, match=match):
                verify_status_list_token("x.y.z", public_key_jwk={}, expected_uri=TOKEN_URI)
        finally:
            issue_mod.verify_compact = original
