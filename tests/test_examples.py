"""
tests/test_examples.py — run every example script end to end so they cannot rot.

Each example is self-contained (mints its own did:key keys, no network). The Data
Integrity one needs pyld, so it is skipped without the [data-integrity] extra.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_EXAMPLES = sorted((Path(__file__).parent.parent / "examples").glob("[0-9]*.py"))


@pytest.mark.parametrize("script", _EXAMPLES, ids=lambda p: p.name)
def test_example_runs(script):
    if "data_integrity" in script.name:
        pytest.importorskip("pyld")
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip(), "example produced no output"
