#!/usr/bin/env python3
"""
Documentation anti-drift checks for openvc (used by the /release skill, STEP 2).

Mechanical, fail-fast checks that catch the drift a human reads past:

  1. Every pip extra named in README.md / CONTRIBUTING.md (openvc[...] or .[...])
     actually exists in pyproject [project.optional-dependencies].
  2. openvc.__version__ matches the top CHANGELOG "## [X.Y.Z]" heading.
  3. Every import / from-import in a README ```python block resolves — the symbol
     still exists (catches renamed/removed public API in the quick-starts).

Run from the repo root:  python .claude/skills/release/scripts/check_docs.py
Exit code 0 = clean, 1 = drift found. Semantic drift (stale prose, ROADMAP
"Done" vs code) is the agent's job in STEP 2; this covers the mechanical part.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# repo root: this file is …/.claude/skills/release/scripts/check_docs.py
ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "src"


def _fail(check: str, msgs: list[str]) -> None:
    print(f"[FAIL] {check}")
    for m in msgs:
        print(f"       - {m}")


def _ok(check: str) -> None:
    print(f"[ok]   {check}")


def _pyproject_extras() -> set[str]:
    text = (ROOT / "pyproject.toml").read_text()
    try:
        import tomllib
        data = tomllib.loads(text)
        return set(data.get("project", {}).get("optional-dependencies", {}))
    except Exception:
        # Fallback: scrape keys under [project.optional-dependencies].
        block = re.search(
            r"\[project\.optional-dependencies\](.*?)(?:\n\[|\Z)", text, re.S)
        if not block:
            return set()
        return set(re.findall(r"^\s*([A-Za-z0-9_-]+)\s*=", block.group(1), re.M))


def check_extras(extras: set[str]) -> list[str]:
    problems: list[str] = []
    for doc in ("README.md", "CONTRIBUTING.md"):
        p = ROOT / doc
        if not p.exists():
            continue
        for m in re.findall(r"(?:openvc|\.)\[([a-z0-9,\s-]+)\]", p.read_text()):
            for name in (n.strip() for n in m.split(",")):
                if name and name not in extras:
                    problems.append(f"{doc}: extra [{name}] is not in pyproject "
                                    f"(known: {sorted(extras)})")
    return problems


def _core(version: str) -> str:
    """The X.Y.Z core, ignoring any .devN/.rcN/etc. pre-release suffix — a dev
    version targets the current unreleased CHANGELOG entry."""
    m = re.match(r"(\d+\.\d+\.\d+)", version)
    return m.group(1) if m else version


def check_version() -> list[str]:
    init = (SRC / "openvc" / "__init__.py").read_text()
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init)
    if not m:
        return ["src/openvc/__init__.py has no __version__"]
    version = m.group(1)
    changelog = (ROOT / "CHANGELOG.md").read_text()
    h = re.search(r"^##\s*\[([0-9][^\]]*)\]", changelog, re.M)
    if not h:
        return ["CHANGELOG.md has no '## [X.Y.Z]' heading"]
    if _core(version) != _core(h.group(1)):
        return [f"__version__ {version!r} (core {_core(version)}) != top "
                f"CHANGELOG heading {h.group(1)!r}"]
    return []


def check_readme_imports() -> list[str]:
    sys.path.insert(0, str(SRC))
    readme = (ROOT / "README.md").read_text()
    problems: list[str] = []
    for block in re.findall(r"```python\n(.*?)```", readme, re.S):
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith(("from openvc", "import openvc")):
                try:
                    exec(compile(stripped, "<readme>", "exec"), {})
                except Exception as exc:
                    problems.append(f"{stripped!r} -> {type(exc).__name__}: {exc}")
    return problems


def main() -> int:
    extras = _pyproject_extras()
    checks = {
        "extras named in docs exist in pyproject": check_extras(extras),
        "__version__ matches CHANGELOG": check_version(),
        "README quick-start imports resolve": check_readme_imports(),
    }
    failed = False
    for name, problems in checks.items():
        if problems:
            failed = True
            _fail(name, problems)
        else:
            _ok(name)
    print("\nDOC DRIFT DETECTED" if failed else "\ndocs are consistent")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
