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


# --------------------------------------------------------------------------- #
# An unreleased fix is filed under a version that has not shipped
# --------------------------------------------------------------------------- #
# GHSA-h9rq-wxcw-4rjc was written up as fixed in 1.33.0 after v1.33.0 had shipped
# without it: an advisory built from that text would have told 1.33.0 users they were
# safe. The unreleased CHANGELOG section must name a version that is not released, and
# the audit docs must file every advisory that section names under that version.

_AUDIT_DOCS = ["docs/audit/threat-model.md", "docs/audit/assurance.md"]
_GHSA_ID = r"GHSA(?:-[0-9a-z]{4}){3}"
_X_Y_Z = r"\d+\.\d+\.\d+"


def _changelog() -> str:
    return _doc_text("CHANGELOG.md")


def _unreleased_section() -> tuple[str, str]:
    text = _changelog()
    match = re.search(rf"^## \[({_X_Y_Z})\] — unreleased$", text, re.M)
    if match is None:
        pytest.skip("no unreleased CHANGELOG section (a release commit)")
    end = text.find("\n## [", match.end())
    return match.group(1), text[match.end():end if end != -1 else None]


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def test_unreleased_changelog_section_names_an_unshipped_version() -> None:
    import openvc

    version, _ = _unreleased_section()
    text = _changelog()
    released = set(re.findall(rf"^\[({_X_Y_Z})\]: \S+/releases/tag/v\1$", text, re.M))
    assert version not in released, f"{version} has a release link: it already shipped"
    assert not re.search(rf"^## \[{re.escape(version)}\] — \d{{4}}-", text, re.M)
    assert _as_tuple(version) > _as_tuple(openvc.__version__), (
        f"the unreleased {version} is not after the package's {openvc.__version__}")


def test_audit_docs_file_unreleased_advisories_under_the_unreleased_version() -> None:
    version, section = _unreleased_section()
    for ghsa in sorted(set(re.findall(_GHSA_ID, section))):
        found = []
        for doc in _AUDIT_DOCS:
            text = _doc_text(doc)
            labels = (re.findall(rf"{ghsa}\W{{1,3}}v({_X_Y_Z})", text)
                      + re.findall(rf"v({_X_Y_Z})\W{{1,3}}{ghsa}", text))
            assert set(labels) <= {version}, f"{doc} files {ghsa} under {labels}"
            found += labels
        assert found, f"no audit doc says which version fixes {ghsa}"


# --------------------------------------------------------------------------- #
# EBSI: `api.ebsi.eu` is a registered host name, not a production API
# --------------------------------------------------------------------------- #
# `EBSI_HOSTS["production"]` is `api.ebsi.eu`, and the wiki said that name was
# "registered for EBSI's Q4 2026 business launch". ADR-0009 measured otherwise on
# 2026-10-16: EBSI Core API v1 has no fixed production host (a client picks a node
# from the signed Trusted Nodes List), and `api.ebsi.eu` returned no HTTP response
# (the certificate it presents does not cover the name). The code and its tests name
# the host legitimately, and so does the threat model's list of registered hosts, so
# this scans for the *claim* ("is the production host", "registered for ... launch"),
# never for the bare string.
_EBSI_HOST = r"api\.ebsi\.eu"
_EBSI_HOST_CLAIMS = [
    # "`production` (`api.ebsi.eu`) is registered for EBSI's Q4 2026 business launch"
    re.compile(r"\bregistered\s+for\b[^.]{0,80}?\blaunch", re.IGNORECASE),
    # "api.ebsi.eu is the production API host" / "... as the production environment"
    re.compile(rf"{_EBSI_HOST}\)?\s+(?:is|as|=)\s+(?:the\s+|EBSI's\s+)?(?:unprefixed\s+)?"
               r"production\b", re.IGNORECASE),
    # "the production host is api.ebsi.eu"
    re.compile(r"\bproduction\s+(?:API\s+|environment\s+)?(?:host(?:name)?|endpoint|base"
               rf"(?:\s+URL)?)\s+(?:is|=|:)\s+{_EBSI_HOST}", re.IGNORECASE),
    # "`production` (`api.ebsi.eu`) is ready" - any positive predicate, but not "is not a node"
    re.compile(rf"\({_EBSI_HOST}\)\s+is\b(?!\s+not\b)", re.IGNORECASE),
]


def _ebsi_host_claims(text: str) -> list[str]:
    plain = re.sub(r"\s+", " ", re.sub(r"[`*]", "", text))   # one line, no markdown
    return [m.group(0) for claim in _EBSI_HOST_CLAIMS for m in claim.finditer(plain)]


@pytest.mark.parametrize("sample, flagged", [
    # the wiki sentence as it read before the correction, on one line and wrapped
    ("`production` (`api.ebsi.eu`) is registered for EBSI's Q4 2026 business launch.", True),
    ("the allow-list from the chosen EBSI environment — `production` (`api.ebsi.eu`) is\n"
     "  registered for EBSI's Q4 2026 business launch. Pass `extra_hosts` to also", True),
    ("`api.ebsi.eu` is registered for EBSI's Q4 2026 business launch.", True),
    ("`api.ebsi.eu` is the production API host.", True),
    ("EBSI's production environment is live: `api.ebsi.eu` as the production base.", True),
    ("The production host is `api.ebsi.eu`.", True),
    ("`production` (`api.ebsi.eu`) is ready at cutover.", True),
    # the threat model lists the registered host names; that is a fact about the code
    ("an https-only **host allow-list**\n  (`api-pilot`/`api-conformance`/`api.ebsi.eu`), "
     "redirects off, TLS-verify on,", False),
    # the corrected wording, and the statements the node-trust page makes about the name
    ("`production` seeds `api.ebsi.eu`, which is not a node: as of 2026-10-16 no HTTP "
     "response could be obtained from it.", False),
    ("`production` (`api.ebsi.eu`) is not a node.", False),
    ("`api.ebsi.eu` returned no HTTP response; the certificate does not cover the name.", False),
    ("Do not match `api.ebsi.*`: none of the 45 node hosts is under `ebsi.eu`.", False),
    ("`for_ebsi(\"production\")` still names `api.ebsi.eu`, kept for compatibility.", False),
    ("the launch event on 2026-10-22 announces an event, not a production API", False),
    ("what the relying party was registered for", False),
])
def test_ebsi_host_claim_scanner(sample: str, flagged: bool) -> None:
    assert bool(_ebsi_host_claims(sample)) is flagged


@pytest.mark.parametrize("page", _CURRENT_DOCS)
def test_docs_do_not_call_api_ebsi_eu_the_production_api(page: str) -> None:
    claims = _ebsi_host_claims(_doc_text(page))
    assert not claims, (
        f"{page} states that api.ebsi.eu is the production API or is registered for a "
        f"launch; ADR-0009 measured (2026-10-16) that it is not a node: {claims}")


def test_trust_page_carries_the_ebsi_node_trust_correction() -> None:
    # The scanner above passes on a page that says nothing, so pin the correction too:
    # removing it must fail, not just restoring the stale sentence.
    trust = re.sub(r"\s+", " ", re.sub(r"[`*]", "", _doc_text("wiki/Trust.md")))
    assert re.search(rf"{_EBSI_HOST}[^.]{{0,40}}\bis not a node\b", trust), (
        "wiki/Trust.md no longer says that `api.ebsi.eu` is not a node")
    assert "legacy pilot lane" in trust, (
        "wiki/Trust.md no longer names for_ebsi('pilot') as the legacy pilot lane")
    for page in ("wiki/Trust.md", "wiki/Spanish-University-Credential.md", "wiki/_Sidebar.md"):
        assert "(EBSI-Node-Trust)" in _doc_text(page), f"{page} no longer links EBSI-Node-Trust"
    assert (_ROOT / "wiki" / "EBSI-Node-Trust.md").exists()
