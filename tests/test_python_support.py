"""
tests/test_python_support.py — Python 3.10 is deprecated, not removed (#241).

CPython 3.10 reached end-of-life on 2026-10-01. openvc 1.x keeps installing and running
on it, but importing openvc there warns once; 2.0 raises ``requires-python`` (#74).

The check is a helper that takes the version, so it is exercised on every interpreter
with simulated ones. The import-time behaviour itself runs in a subprocess, never by
reloading the package in-process (that rebinds module globals and breaks class identity
for the rest of the suite): ``import openvc`` must fail under
``-W error:openvc:FutureWarning`` on 3.10 and nowhere else.
"""
from __future__ import annotations

import os
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from openvc._python_support import python_deprecation_message, warn_if_python_deprecated

PY310 = (3, 10, 22, "final", 0)
SUPPORTED = [(3, 11, 0, "final", 0), (3, 12, 0, "final", 0), (3, 13, 0, "final", 0),
             (3, 14, 0, "final", 0), (3, 15, 0, "final", 0)]


def test_the_310_message_names_the_eol_the_removal_and_the_way_forward():
    message = python_deprecation_message(PY310)
    assert message is not None
    assert message.startswith("openvc: Python 3.10")
    assert "end-of-life on 2026-10-01" in message
    assert "openvc 1.x still installs and runs on it" in message
    assert "openvc 2.0 will require Python 3.11 or later" in message
    assert "issues/74" in message


@pytest.mark.parametrize("version", SUPPORTED, ids=lambda v: f"{v[0]}.{v[1]}")
def test_supported_pythons_get_no_message(version):
    assert python_deprecation_message(version) is None


def test_310_warns_with_a_futurewarning():
    # FutureWarning, not DeprecationWarning: the latter is hidden by default outside
    # __main__, and an import-time warning is attributed to importlib's frames.
    with pytest.warns(FutureWarning, match="end-of-life on 2026-10-01"):
        warn_if_python_deprecated(PY310)


@pytest.mark.parametrize("version", SUPPORTED, ids=lambda v: f"{v[0]}.{v[1]}")
def test_supported_pythons_stay_silent(version):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        warn_if_python_deprecated(version)


def test_the_running_interpreter_is_judged_by_default():
    expected = sys.version_info[:2] == (3, 10)
    assert (python_deprecation_message() is not None) is expected


def test_importing_openvc_warns_only_on_310():
    src = str(Path(__file__).resolve().parent.parent / "src")
    env = {**os.environ, "PYTHONPATH": src + os.pathsep + os.environ.get("PYTHONPATH", "")}
    # The filter's message field is a literal prefix: only openvc's own notice
    # ("openvc: Python …") is turned into an error, never a dependency's FutureWarning.
    proc = subprocess.run(
        [sys.executable, "-W", "error:openvc:FutureWarning", "-c", "import openvc"],
        capture_output=True, text=True, env=env, timeout=120)
    if sys.version_info[:2] == (3, 10):
        assert proc.returncode != 0
        assert "end-of-life on 2026-10-01" in proc.stderr
    else:
        assert proc.returncode == 0, proc.stderr
