"""openvc.status — credential status / revocation.

Two status-list encodings behind one interface:

* **W3C Bitstring Status List** (``bitstring`` + ``status_list``) — MSB-first
  bits, gzip, referenced by a VC ``credentialStatus`` entry.
* **IETF Token Status List** (``token_status_list``) — 1/2/4/8-bit LSB-first
  statuses, DEFLATE/zlib, referenced by a token ``status`` claim.
"""

from .bitstring import (
    StatusListError,
    decode_bitstring,
    encode_bitstring,
    get_status_bit,
    new_bitstring,
    set_status_bit,
)
from .issue import (
    STATUS_LIST_JWT_TYP,
    build_status_list_credential,
    build_status_list_entry,
    build_status_list_token,
    build_token_status_reference,
    verify_status_list_token,
)
from .status_list import (
    CredentialRevoked,
    ResolveStatusList,
    StatusEntry,
    StatusEntryResult,
    StatusResult,
    check_credential_status,
    parse_status_entries,
)
from .token_status_list import (
    STATUS_INVALID,
    STATUS_SUSPENDED,
    STATUS_VALID,
    ResolveStatusListToken,
    TokenStatusRef,
    TokenStatusResult,
    check_token_status,
    decode_status_list,
    encode_status_list,
    get_status,
    new_status_list,
    parse_token_status_ref,
    set_status,
)

__all__ = [
    # W3C Bitstring Status List
    "StatusListError",
    "decode_bitstring",
    "encode_bitstring",
    "get_status_bit",
    "new_bitstring",
    "set_status_bit",
    "CredentialRevoked",
    "ResolveStatusList",
    "StatusEntry",
    "StatusEntryResult",
    "StatusResult",
    "check_credential_status",
    "parse_status_entries",
    # IETF Token Status List
    "STATUS_VALID",
    "STATUS_INVALID",
    "STATUS_SUSPENDED",
    "ResolveStatusListToken",
    "TokenStatusRef",
    "TokenStatusResult",
    "check_token_status",
    "decode_status_list",
    "encode_status_list",
    "get_status",
    "new_status_list",
    "parse_token_status_ref",
    "set_status",
    # issuer-side construction
    "build_status_list_credential",
    "build_status_list_entry",
    "build_status_list_token",
    "verify_status_list_token",
    "build_token_status_reference",
    "STATUS_LIST_JWT_TYP",
]
