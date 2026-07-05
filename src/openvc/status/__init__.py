"""openvc.status — credential status / revocation (W3C Bitstring Status List)."""

from .bitstring import (
    StatusListError,
    decode_bitstring,
    encode_bitstring,
    get_status_bit,
    set_status_bit,
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

__all__ = [
    "StatusListError",
    "decode_bitstring",
    "encode_bitstring",
    "get_status_bit",
    "set_status_bit",
    "CredentialRevoked",
    "ResolveStatusList",
    "StatusEntry",
    "StatusEntryResult",
    "StatusResult",
    "check_credential_status",
    "parse_status_entries",
]
