"""
openvc_ebsi._message — what a value may look like inside an error message.

An error message reaches logs, so a value in it is cut and a credential in it is withheld:

  * :func:`url_repr` is ``safe_repr`` for a URL: the userinfo is replaced by ``***`` BEFORE the
    cut, so a 200-character cut cannot leave ``https://user:pas`` showing (#351);
  * :func:`bounded_text` cuts a string that is not a URL (a transport error's own text, a
    list of credential types) and, unlike ``safe_repr``, does not quote it, so a message that
    already read ``gave up after 3 attempts: transient`` reads the same.

Only the message changes. An exception's ``.url`` keeps the URL as given (#343): the caller who
passed it already holds its password, and the message is what reaches a log.

A leaf module: it imports ``openvc`` and nothing of this package.
"""

from __future__ import annotations

import re
from typing import Any

from openvc.proof._verify_common import _SHOWN_MAX, safe_repr

REDACTED = "***"
_WITHHELD = "<url withheld>"

# What `urlsplit` ignores before it reads a URL: a tab, a carriage return and a line feed
# anywhere, and a leading C0 control or space. The authority is looked for in the URL as the
# reader that fetches it sees it.
_DROPPED = {ord(c): None for c in "\t\r\n"}
_LEADING = "".join(chr(c) for c in range(0x21))
# the scheme may be empty: httpx reads `://user:pass@host/` as an authority
_SCHEME = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.\-]*)?:")
_SLASHES = re.compile(r"[/\\]*")
_AUTHORITY_END = re.compile(r"[/?#]")
_DELIMITER = re.compile(r"@|%40", re.IGNORECASE)


def redact_userinfo(url: str) -> str:
    """*url* with the userinfo of its authority replaced by ``***``, or *url* unchanged when its
    authority holds none.

    The authority follows a run of ``/`` and ``\\`` characters, after an optional (possibly
    empty) ``scheme:``: one slash opens it after a scheme and two do without one, because a
    WHATWG parser reads ``http:/u:p@h`` and ``http:///u:p@h`` as ``http://u:p@h``. It ends at the
    first ``/``, ``?`` or ``#``. The userinfo is everything in it up to the LAST ``@``, which is
    where ``urlparse`` and httpx both split: ``https://u:p@ss@host/`` has the userinfo
    ``u:p@ss``. An ``@`` in a path, query or fragment is not userinfo and stays. The whole
    userinfo is withheld, the user name included, and so are the empty forms
    (``https://@host/``). A percent-encoded ``@`` (``%40``) counts as a delimiter too, because a
    URL written ``user:pass%40host`` has no userinfo for a parser and its password still sits in
    front of the host. A reference with no slashes is read the same way from its first
    character (``user:pass@host/x``, ``mailto:a@b``, where ``user:`` would read as a scheme): it
    is no URL a client would send, and what it holds before an ``@`` is more likely a credential
    than not.

    Linear in the length of *url*, whatever its shape. Nothing raises: a value that cannot be
    read returns a fixed placeholder, never the input. A ``str`` subclass is read through
    ``str.__str__``, never its own methods."""
    try:
        text = str.__str__(url)
        view = text.translate(_DROPPED).lstrip(_LEADING)
        scheme = _SCHEME.match(view)
        after = scheme.end() if scheme else 0
        run = _SLASHES.match(view, after)         # always matches: it may match nothing
        slashes = run.end() if run else after
        # A WHATWG parser skips every `/` and `\` after a special scheme, one included
        # (`http:/u:p@h`, `http:///u:p@h`), and `//` opens an authority with no scheme at all;
        # a lone `/x@y` is a path.
        start = slashes if slashes > after + (0 if scheme else 1) else 0
        end = _AUTHORITY_END.search(view, start)
        authority = view[start:end.start() if end else len(view)]
        userinfo_end = 0                      # where the host begins: after the last delimiter
        for delimiter in _DELIMITER.finditer(authority):
            userinfo_end = delimiter.end()
        if not userinfo_end:
            return text
        return (f"{view[:start]}{REDACTED}@{authority[userinfo_end:]}"
                f"{view[start + len(authority):]}")
    except Exception:
        return _WITHHELD


def url_repr(value: Any) -> str:
    """*value* for an error message when it is a URL, or may be one: ``safe_repr`` of it with
    the userinfo of a ``str`` withheld first. Anything that is not a ``str`` goes to
    ``safe_repr`` as it is."""
    if isinstance(value, str):
        value = redact_userinfo(value)
        if value is _WITHHELD:              # not a str at all, whatever it says: as safe_repr does
            return "an object"
    return safe_repr(value)


def bounded_text(value: Any) -> str:
    """``str(value)`` for an error message, cut past ``safe_repr``'s 200 characters with the
    length it had, and not quoted. A value whose ``__str__`` raises is ``an object``."""
    try:
        text = str.__str__(str(value))        # a subclass's methods may raise or lengthen
    except Exception:
        return "an object"
    if len(text) <= _SHOWN_MAX:
        return text
    return f"{text[:_SHOWN_MAX]}... ({len(text)} chars)"
