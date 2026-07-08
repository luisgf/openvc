"""
tests/test_docs_links.py — every internal wiki link resolves.

GitHub wiki links are by page name (``[text](Page-Name)``), so renaming or
deleting a page breaks inbound links silently — no 404 shows up in CI unless
we look. This asserts every internal link in wiki/*.md points at an existing
wiki page. External (scheme-ful) links are out of scope here.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_WIKI = Path(__file__).parent.parent / "wiki"
_PAGES = sorted(_WIKI.glob("*.md"))

# [text](Target) / [text](Target#anchor) — the group is the pre-anchor target.
_LINK = re.compile(r"\[[^\]]+\]\(([^)#\s]+)(?:#[^)\s]*)?\)")


def _internal_targets(text: str):
    for target in _LINK.findall(text):
        if "://" in target or target.startswith("mailto:"):
            continue
        yield target


def test_wiki_has_pages() -> None:
    """The glob keeps finding the wiki sources (guards a directory rename)."""
    assert len(_PAGES) >= 3, "wiki/ pages not found — did the directory move?"


@pytest.mark.parametrize("page", _PAGES, ids=lambda p: p.name)
def test_wiki_internal_links_resolve(page: Path) -> None:
    names = {p.stem for p in _PAGES}
    missing = [t for t in _internal_targets(page.read_text(encoding="utf-8"))
               if t not in names]
    assert not missing, f"{page.name} links to missing wiki page(s): {missing}"
