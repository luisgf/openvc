"""
openvc_ebsi._url — the one reader of a URL's origin.

Two checks in this package look at the same URL and must agree on what it names:

  * the HTTP client's SSRF guard (``http.EbsiHttpClient._guard_host``), which refuses a
    request that is not ``https`` on an allow-listed host at port 443 (#318), and
  * the origin pin of the TIR v5 adapter (``versioning._origin``), which keeps a registry
    walk on the node it started on (#172, #253).

Both read the URL here, so a rule about scheme, host or port (an absent https port is 443,
and only an absent one) is written once. A leaf module: it imports nothing of this package,
so the adapters need not import the transport module, and the transport need not import
the adapters. The two private errors say *why* a URL has no origin; each caller maps them to
its own public class and message.
"""

from __future__ import annotations

from typing import NamedTuple
from urllib.parse import ParseResult, urlparse

# The port an absent one stands for. Only https: the HTTP client refuses anything else, so
# an http URL keeps an empty port and can never match an https listing anyway.
HTTPS_PORT = 443
DEFAULT_PORTS = {"https": HTTPS_PORT}


class UrlError(Exception):
    """A URL with no origin to read. Deliberately not a ``ValueError``: a caller that
    forgets to map it fails loudly rather than being caught by an ``except ValueError``."""


class UrlNotVisibleAscii(UrlError):
    """Not visible ASCII (a control character, a space, a non-ASCII character)."""


class UrlDoesNotParse(UrlError):
    """``urlparse`` cannot read it, port included. ``__cause__`` is a ``ValueError`` of fixed
    words, not ``urlparse``'s own, whose text quotes the part of the URL it could not read (a
    port that is a password, #351)."""


class Origin(NamedTuple):
    scheme: str                 # lowercased
    host: str                   # lowercased; "" when the URL names none
    port: int | None            # an absent https port is 443; any other absent port is None


def _split(url: str) -> tuple[ParseResult, int | None]:
    # A URL is checked by `urlparse` here and fetched by httpx, which reads some URLs
    # differently: urlsplit drops a tab or newline and ignores other control characters
    # that httpx rejects. Refuse anything that is not visible ASCII BEFORE `urlparse`
    # reads it (on CPython <= 3.12 it NFKC-normalizes a non-ASCII netloc in quadratic
    # time), and a URL `urlparse` cannot read, port included (#246).
    if not (url.isascii() and url.isprintable()) or " " in url:
        raise UrlNotVisibleAscii()
    # `urlparse`'s own ValueError quotes the text it could not read: a port that is not a
    # number is echoed whole (`https://user:s3cret%40host/x` reads `s3cret%40host` as the port
    # and says so, 70 000 characters of it if the port is that long). The cause is therefore
    # a ValueError of fixed words, raised outside the `except` so the original is not chained
    # as `__context__` either (#351).
    refusal = None
    try:
        parsed = urlparse(url)            # raises on a broken IPv6 literal
        port = parsed.port                # raises on an out-of-range or non-numeric port
    except ValueError:
        refusal = "the authority is not a valid host and port"
    if refusal is not None:
        raise UrlDoesNotParse() from ValueError(refusal)
    return parsed, port


def read_origin(url: str) -> Origin:
    """The ``(scheme, host, port)`` of ``url``, scheme and host lowercased.

    An absent port is the scheme's default (RFC 3986 section 6.2.3), so ``https://host``,
    ``https://host:`` and ``https://host:443`` are one origin, as they are to httpx (#253).
    Only an ABSENT port is filled in, and only for https: ``port is None``, never
    truthiness, so an explicit ``:0`` stays port 0 and is not the default. Userinfo is not
    part of an origin and is ignored here; :func:`carries_userinfo` reports it.

    Raises:
        UrlNotVisibleAscii: ``url`` is not visible ASCII (checked before ``urlparse``).
        UrlDoesNotParse: ``urlparse`` cannot read it (a bad port, a broken IPv6 literal)."""
    parsed, port = _split(url)
    scheme = parsed.scheme.lower()
    if port is None:                      # `is None`: port 0 is falsy, not absent
        port = DEFAULT_PORTS.get(scheme)
    return Origin(scheme, (parsed.hostname or "").lower(), port)


def carries_userinfo(url: str) -> bool:
    """Whether the authority of ``url`` holds userinfo, the empty forms ``https://@host/``
    and ``https://:@host/`` included. An ``@`` can only sit in the authority as the
    userinfo delimiter, and ``urlparse`` ends the authority at the first ``/``, ``?`` or
    ``#``, so an ``@`` in a path, query or fragment does not count. Same refusals as
    :func:`read_origin`."""
    parsed, _ = _split(url)
    return "@" in parsed.netloc
