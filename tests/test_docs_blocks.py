"""
tests/test_docs_blocks.py — execute every ```python block in README.md and the
wiki/ sources so the documentation cannot rot: a renamed function, a changed
signature, or a moved import in a documented snippet fails CI, exactly like
tests/test_examples.py does for the example scripts.

Snippets must be self-contained and offline (they are documentation of the
offline-testable surface). Two escape hatches, as an HTML comment on the line
directly above the fence:

    <!-- docs: no-run -->         illustrative only (placeholders, network) — skip
    <!-- docs: needs=pyld -->     run only when that module is importable

Blocks in any other language (```sh, ```yaml, …) are ignored.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent.parent
_DOC_FILES = [_ROOT / "README.md", *sorted((_ROOT / "wiki").glob("*.md"))]

# An optional `<!-- docs: ... -->` directive line, then a ```python fence.
_BLOCK = re.compile(
    r"(?:<!--\s*docs:\s*(?P<directive>[^>]*?)\s*-->\s*\n\s*)?"
    r"```python[^\n]*\n(?P<code>.*?)^```",
    re.DOTALL | re.MULTILINE,
)


def _blocks():
    for path in _DOC_FILES:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for n, match in enumerate(_BLOCK.finditer(text), start=1):
            yield pytest.param(
                match.group("directive") or "",
                match.group("code"),
                id=f"{path.name}:{n}",
            )


@pytest.mark.parametrize(("directive", "code"), list(_blocks()))
def test_doc_block_runs(directive: str, code: str) -> None:
    if "no-run" in directive:
        pytest.skip("marked <!-- docs: no-run -->")
    needs = re.search(r"needs=([A-Za-z0-9_.]+)", directive)
    if needs:
        pytest.importorskip(needs.group(1))
    exec(compile(code, "<doc-block>", "exec"), {"__name__": "__doc_block__"})


def test_docs_have_blocks() -> None:
    """The extractor keeps finding blocks — guards against a regex/format change
    silently turning this whole module into a no-op."""
    assert len(list(_blocks())) >= 2
