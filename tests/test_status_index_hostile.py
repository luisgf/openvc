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
from openvc.keys import P256SigningKey
from openvc.proof.sd_jwt import SdJwtVcProofSuite
from openvc.proof.vc_jwt import VcJwtProofSuite
from openvc.status import (
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
