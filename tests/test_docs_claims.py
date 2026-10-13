"""
tests/test_docs_claims.py — pin specific documentation claims to the code.

Prose drifts in ways executable snippets don't catch, and each assertion here
guards a claim that has actually drifted once in this repo's history:

- the pyproject ``description`` once said "VC-JWT and DID resolution (key/web)"
  long after SD-JWT VC / Data Integrity / status lists shipped;
- the threat model once said the allow-list was ``{ES256, EdDSA}`` while the
  code enforced ``{ES256, ES384, EdDSA}``; after RFC 9864 added ``Ed25519``
  (v1.11.0) the README capability table and the ``SigningKey.alg`` comment kept
  the three-name list;
- the README's install section lagged the extras in pyproject;
- ``did:webvh`` joined the default resolver after this file was first written.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path
from typing import Any, Callable

import pytest

from openvc.aio import default_async_resolver
from openvc.did.base import DidResolutionError, UnsupportedDidMethod
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import ALLOWED_ALGS
from openvc.verify import default_resolver

_ROOT = Path(__file__).parent.parent
_PYPROJECT = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
_README = (_ROOT / "README.md").read_text(encoding="utf-8")
_WIKI_PAGES = sorted((_ROOT / "wiki").glob("*.md"))
# Every doc that describes the library as it is now. ADRs and the session
# handoff are point-in-time records, so they may quote what was true then.
_CURRENT_DOCS = ["README.md", "SECURITY.md", "docs/index.md",
                 *(f"wiki/{p.name}" for p in _WIKI_PAGES),
                 *(str(p.relative_to(_ROOT)) for sub in ("api", "audit")
                   for p in sorted((_ROOT / "docs" / sub).glob("*.md")))]


def _doc_text(doc: str) -> str:
    path = _ROOT / doc
    assert path.exists(), f"{doc} is gone — update the docs this test pins"
    return path.read_text(encoding="utf-8")


def test_wiki_is_in_the_tree() -> None:
    # Every wiki-scanning test below parametrizes over this glob; an empty glob
    # would make them pass by collecting nothing.
    assert _WIKI_PAGES, "wiki/*.md not found"


# --------------------------------------------------------------------------- #
# Extras ↔ install documentation
# --------------------------------------------------------------------------- #

def _extras() -> set[str]:
    section = re.search(
        r"\[project\.optional-dependencies\]\n(.*?)\n\[", _PYPROJECT, re.DOTALL)
    assert section, "optional-dependencies section not found in pyproject.toml"
    return {m.group(1)
            for m in re.finditer(r"^([A-Za-z0-9-]+)\s*=", section.group(1), re.MULTILINE)}


# dev/docs are contributor tooling, documented in CONTRIBUTING, not the README.
_USER_FACING = sorted(_extras() - {"dev", "docs"})


@pytest.mark.parametrize("extra", _USER_FACING)
def test_readme_documents_every_extra(extra: str) -> None:
    assert f"openvc-core[{extra}]" in _README, (
        f"pyproject defines the extra {extra!r} but the README install section "
        f"never mentions openvc-core[{extra}]")


@pytest.mark.parametrize("extra", _USER_FACING)
def test_wiki_getting_started_documents_every_extra(extra: str) -> None:
    assert f"openvc-core[{extra}]" in _doc_text("wiki/Getting-Started.md")


# --------------------------------------------------------------------------- #
# The JOSE algorithm allow-list ↔ every doc that talks about it
# --------------------------------------------------------------------------- #

# Superset of algs docs could plausibly name. If a doc legitimately starts
# discussing one outside ALLOWED_ALGS (e.g. "ES512 is rejected"), that is a
# conscious wording decision — spell it without the bare token (as the docs
# already do for RS*/HS*) or extend this test deliberately.
_ALG_CANDIDATES = {"ES256", "ES384", "ES512", "EdDSA", "Ed25519", "RS256", "PS256", "HS256"}

# Whole tokens only: `Ed25519SigningKey` is a class, `ES256K` another algorithm.
_ALG = "|".join(sorted(_ALG_CANDIDATES, key=len, reverse=True))
_ALG_TOKEN = re.compile(rf"(?<![A-Za-z0-9])(?:{_ALG})(?![A-Za-z0-9])")

_ALG_DOCS = ["README.md", "wiki/VC-JWT.md", "wiki/Security-Model.md",
             "wiki/Keys-and-HSM.md", "wiki/Getting-Started.md"]


@pytest.mark.parametrize("doc", _ALG_DOCS)
def test_docs_quote_the_real_allow_list(doc: str) -> None:
    mentioned = set(_ALG_TOKEN.findall(_doc_text(doc)))
    assert mentioned == set(ALLOWED_ALGS), (
        f"{doc} names the algorithms {sorted(mentioned)} but the code's "
        f"ALLOWED_ALGS is {sorted(ALLOWED_ALGS)}")


# `Ed25519` is also the curve and key name, so the token check above cannot tell
# "lists the allow-list" from "mentions an Ed25519 key". These pin the statements
# themselves: a prose set `{A, B, …}` (no quotes — a quoted Python set in a
# snippet may narrow the list on purpose), or a run of three or more names joined
# by `/`, `|` or `,`, must be exactly ALLOWED_ALGS.
_BRACE_SET = re.compile(r"\{([^{}\n]*)\}")
_RUN_ITEM = rf"[`\"]?(?<![A-Za-z0-9])(?:{_ALG})(?![A-Za-z0-9])[`\"]?"
_ALG_RUN = re.compile(rf"{_RUN_ITEM}(?:\s*[/|,]\s*{_RUN_ITEM})+")

# A page may quote a *past* allow-list on purpose. Each such set is listed with
# its page, so every other statement on that page is still checked.
_HISTORICAL_ALG_SETS = {
    # "`Ed25519` joined the `{ES256, ES384, EdDSA}` allow-list" (RFC 9864, #59)
    "Versioning-and-Deprecation.md": {frozenset({"ES256", "ES384", "EdDSA"})},
}


def _alg_statements(text: str) -> list[tuple[int, frozenset[str]]]:
    """(line, algorithms) for every allow-list statement in *text*."""
    found: list[tuple[int, frozenset[str]]] = []
    brace_spans: list[tuple[int, int]] = []
    for m in _BRACE_SET.finditer(text):
        items = [t for t in re.split(r"[\s,`]+", m.group(1)) if t]
        if len(items) >= 2 and all(t in _ALG_CANDIDATES for t in items):
            brace_spans.append(m.span())
            found.append((text.count("\n", 0, m.start()) + 1, frozenset(items)))
    for m in _ALG_RUN.finditer(text):
        if any(lo <= m.start() < hi for lo, hi in brace_spans):
            continue
        items = _ALG_TOKEN.findall(m.group(0))
        if len(items) >= 3:
            found.append((text.count("\n", 0, m.start()) + 1, frozenset(items)))
    return found


@pytest.mark.parametrize("sample, expected", [
    ("the `{ES256, EdDSA}` allow-list", [frozenset({"ES256", "EdDSA"})]),
    ("VC-JWT (`ES256` / `ES384` / `EdDSA`)", [frozenset({"ES256", "ES384", "EdDSA"})]),
    ('alg: "ES256" | "ES384" | "EdDSA"', [frozenset({"ES256", "ES384", "EdDSA"})]),
    ('allowed_algs=frozenset({"ES256"})', []),          # a snippet narrowing on purpose
    ("`ES256`/`ES384` are not deprecated", []),         # two names: not the whole list
    ("an Ed25519SigningKey, ES256K", []),
])
def test_alg_statement_scanner(sample: str, expected: list[frozenset[str]]) -> None:
    assert [algs for _, algs in _alg_statements(sample)] == expected


@pytest.mark.parametrize("page", _CURRENT_DOCS)
def test_allow_list_statements_match_the_code(page: str) -> None:
    historical = _HISTORICAL_ALG_SETS.get(Path(page).name, set())
    wrong = [(line, sorted(algs)) for line, algs in _alg_statements(_doc_text(page))
             if algs != ALLOWED_ALGS and algs not in historical]
    assert not wrong, (
        f"{page} states an allow-list other than ALLOWED_ALGS "
        f"{sorted(ALLOWED_ALGS)} at (line, algs): {wrong}")


def test_historical_alg_sets_are_still_quoted() -> None:
    # A stale exemption would silently re-admit that set on its page.
    for name, sets in _HISTORICAL_ALG_SETS.items():
        quoted = {algs for _, algs in _alg_statements(_doc_text(f"wiki/{name}"))}
        assert sets <= quoted, f"wiki/{name} no longer quotes {sets - quoted}"


# --------------------------------------------------------------------------- #
# DID methods: what the default pipeline resolves ↔ what the docs promise
# --------------------------------------------------------------------------- #

_CORE_METHODS = ("did:key", "did:jwk", "did:web", "did:webvh")


def _sync_resolve(did: str) -> Any:
    return default_resolver().resolve(did)


def _async_resolve(did: str) -> Any:
    return asyncio.run(default_async_resolver().resolve(did))


@pytest.mark.parametrize("resolve", [_sync_resolve, _async_resolve], ids=["sync", "async"])
def test_default_resolver_supports_the_documented_methods(
        resolve: Callable[[str], Any]) -> None:
    raw = Ed25519SigningKey.generate(kid="_").public_key_raw()
    did_key = "did:key:" + encode_multibase(bytes([0xED, 0x01]) + raw)
    assert resolve(did_key).verification_methods

    jwk = Ed25519SigningKey.generate(kid="_").public_jwk()
    did_jwk = "did:jwk:" + base64.urlsafe_b64encode(
        json.dumps(jwk).encode()).rstrip(b"=").decode()
    assert resolve(did_jwk).verification_methods

    # did:web / did:webvh are network-backed. A malformed host fails inside the
    # method's resolver, before any I/O — a DidResolutionError, which
    # UnsupportedDidMethod is not, proves the registry dispatched it.
    for did in ("did:web:bad_host", "did:webvh:QmSCID:bad_host"):
        with pytest.raises(DidResolutionError, match="not a domain name"):
            resolve(did)

    # did:ebsi is plugin territory — the core default must NOT claim it.
    with pytest.raises(UnsupportedDidMethod):
        resolve("did:ebsi:zExample")


@pytest.mark.parametrize("doc", ["README.md", "wiki/Resolving-Issuer-Keys.md"])
def test_docs_name_the_core_did_methods(doc: str) -> None:
    text = _doc_text(doc)
    for method in _CORE_METHODS:
        assert f"`{method}`" in text, f"{doc} does not document {method}"


# --------------------------------------------------------------------------- #
# pyproject description ↔ README tagline
# --------------------------------------------------------------------------- #

def test_pypi_description_matches_readme_pitch() -> None:
    match = re.search(r'^description = "(.+)"$', _PYPROJECT, re.MULTILINE)
    assert match, "description not found in pyproject.toml"
    description = match.group(1)
    readme_head = "\n".join(_README.splitlines()[:30])
    for token in ("Verifiable Credentials core", "VC-JWT", "SD-JWT", "Data Integrity",
                  "OpenID4VP"):
        assert token in description, f"pyproject description lost {token!r}"
        assert token in readme_head, f"README opening lost {token!r}"


# --------------------------------------------------------------------------- #
# No version literal stated as current
# --------------------------------------------------------------------------- #

# A version stated as *current* goes stale on the next release; the single source
# of truth is openvc.__version__. A dated note ("Before 1.31.0 …", "since 1.30.2")
# does not, so this does not ban the current version string: the release gate runs
# after the bump, where such a note for the release being cut would match.
_SEMVER = r"v?\d+\.\d+\.\d+"
_STALE_VERSION_FORMS = [
    # an exact pin turns into a downgrade instruction one release later
    re.compile(rf"openvc(?:-core)?(?:\[[^\]\s]*\])?\s*==\s*{_SEMVER}"),
    # the package version written out as a value (an assignment, a REPL echo)
    re.compile(rf"__version__\W{{0,12}}?{_SEMVER}"),
    # "the current/latest version is X.Y.Z"
    re.compile(rf"\b(?:current|latest)\s+(?:stable\s+)?(?:version|release)\b"
               rf"[^\n.]{{0,30}}?\b{_SEMVER}", re.IGNORECASE),
]


def _stale_version_claims(text: str) -> list[str]:
    return [m.group(0) for form in _STALE_VERSION_FORMS for m in form.finditer(text)]


@pytest.mark.parametrize("sample, stale", [
    ("pip install openvc-core==1.9.0", True),
    ('pip install "openvc-core[all]==1.9.0"', True),
    (">>> openvc.__version__\n'1.9.0'", True),
    ("openvc.__version__  # '1.9.0'", True),
    ("The current release is 1.9.0.", True),
    ("the latest version (v1.9.0)", True),
    ("Before 1.31.0, an IETF list", False),
    ("required, since 1.30.2, that the JSON", False),
    ("pip install 'openvc-core>=1.30.2'", False),        # a floor does not go stale
    ("guaranteed to run against the current release.", False),
])
def test_stale_version_scanner(sample: str, stale: bool) -> None:
    assert bool(_stale_version_claims(sample)) is stale


@pytest.mark.parametrize("page", _CURRENT_DOCS)
def test_docs_do_not_state_a_current_version(page: str) -> None:
    claims = _stale_version_claims(_doc_text(page))
    assert not claims, f"{page} states a version as current: {claims}"
