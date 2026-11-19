"""Import failure handling for the reporter's test module."""

import importlib.machinery
import importlib.util
import runpy
from pathlib import Path

import pytest

TEST_MODULE = (
    Path(__file__).resolve().parents[2] / "reporter/test_abuseipdb_reporter.py"
)


@pytest.mark.parametrize(
    "spec", [None, importlib.machinery.ModuleSpec("missing", None)]
)
def test_missing_spec_or_loader_fails_clearly(monkeypatch, spec):
    monkeypatch.setattr(importlib.util, "spec_from_file_location", lambda *args: spec)
    with pytest.raises(RuntimeError, match="cannot load reporter module"):
        runpy.run_path(str(TEST_MODULE))
