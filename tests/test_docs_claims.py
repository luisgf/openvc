"""
tests/test_docs_claims.py — pin specific documentation claims to the code.

Prose drifts in ways executable snippets don't catch, and each assertion here
guards a claim that has actually drifted once in this repo's history:

- the pyproject ``description`` once said "VC-JWT and DID resolution (key/web)"
  long after SD-JWT VC / Data Integrity / status lists shipped;
- the threat model once said the allow-list was ``{ES256, EdDSA}`` while the
  code enforced ``{ES256, ES384, EdDSA}``;
- the README's install section lagged the extras in pyproject.

Wiki pages are checked when present (they land in their own PR; the checks
skip, not fail, while ``wiki/`` is absent).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import base64
import json

from openvc import __version__
from openvc.did.base import UnsupportedDidMethod
from openvc.fetch import default_did_web_resolver
from openvc.keys import Ed25519SigningKey
from openvc.multibase import encode_multibase
from openvc.proof.vc_jwt import ALLOWED_ALGS
from openvc.verify import default_resolver

_ROOT = Path(__file__).parent.parent
_PYPROJECT = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
_README = (_ROOT / "README.md").read_text(encoding="utf-8")


def _wiki_text(name: str) -> str:
    path = _ROOT / "wiki" / name
    if not path.exists():
        pytest.skip(f"wiki/{name} not in this tree yet")
    return path.read_text(encoding="utf-8")


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
    text = _wiki_text("Getting-Started.md")
    assert f"openvc-core[{extra}]" in text


# --------------------------------------------------------------------------- #
# The JOSE algorithm allow-list ↔ every doc that talks about it
# --------------------------------------------------------------------------- #

# Superset of algs docs could plausibly name. If a doc legitimately starts
# discussing one outside ALLOWED_ALGS (e.g. "ES512 is rejected"), that is a
# conscious wording decision — spell it without the bare token (as the docs
# already do for RS*/HS*) or extend this test deliberately.
_ALG_CANDIDATES = {"ES256", "ES384", "ES512", "EdDSA", "RS256", "PS256", "HS256"}

_ALG_DOCS = ["README.md", "wiki/VC-JWT.md", "wiki/Security-Model.md",
             "wiki/Keys-and-HSM.md", "wiki/Getting-Started.md"]


@pytest.mark.parametrize("doc", _ALG_DOCS)
def test_docs_quote_the_real_allow_list(doc: str) -> None:
    if doc.startswith("wiki/"):
        text = _wiki_text(doc.removeprefix("wiki/"))
    else:
        text = _README
    mentioned = {alg for alg in _ALG_CANDIDATES if alg in text}
    assert mentioned == set(ALLOWED_ALGS), (
        f"{doc} names the algorithms {sorted(mentioned)} but the code's "
        f"ALLOWED_ALGS is {sorted(ALLOWED_ALGS)}")


# --------------------------------------------------------------------------- #
# DID methods: what the default pipeline resolves ↔ what the docs promise
# --------------------------------------------------------------------------- #

_CORE_METHODS = ("did:key", "did:jwk", "did:web")


def test_default_resolver_supports_the_documented_methods() -> None:
    registry = default_resolver()

    raw = Ed25519SigningKey.generate(kid="_").public_key_raw()
    did_key = "did:key:" + encode_multibase(bytes([0xED, 0x01]) + raw)
    assert registry.resolve(did_key).verification_methods

    jwk = Ed25519SigningKey.generate(kid="_").public_jwk()
    did_jwk = "did:jwk:" + base64.urlsafe_b64encode(
        json.dumps(jwk).encode()).rstrip(b"=").decode()
    assert registry.resolve(did_jwk).verification_methods

    # did:web is network-backed: assert method support via its (no-I/O) predicate.
    assert default_did_web_resolver().supports("did:web:issuer.example")

    # did:ebsi is plugin territory — the core default must NOT claim it.
    with pytest.raises(UnsupportedDidMethod):
        registry.resolve("did:ebsi:zExample")


@pytest.mark.parametrize("doc", ["README.md", "wiki/Resolving-Issuer-Keys.md"])
def test_docs_name_the_core_did_methods(doc: str) -> None:
    text = _README if doc == "README.md" else _wiki_text(doc.removeprefix("wiki/"))
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
    for token in ("Verifiable Credentials core", "VC-JWT", "SD-JWT", "Data Integrity"):
        assert token in description, f"pyproject description lost {token!r}"
        assert token in readme_head, f"README opening lost {token!r}"


# --------------------------------------------------------------------------- #
# No hardcoded current version anywhere in the docs
# --------------------------------------------------------------------------- #

def test_docs_do_not_hardcode_the_version() -> None:
    """A literal current version in prose goes stale on the next release; the
    single source of truth is openvc.__version__."""
    offenders = [p.name for p in [_ROOT / "README.md", *(_ROOT / "wiki").glob("*.md")]
                 if p.exists() and __version__ in p.read_text(encoding="utf-8")]
    assert not offenders, f"docs hardcode version {__version__}: {offenders}"
