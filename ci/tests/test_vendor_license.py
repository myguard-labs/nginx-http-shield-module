#!/usr/bin/env python3
"""Require license text and disclosure for vendored Apache-2.0 rules."""

from pathlib import Path

root = Path(__file__).parents[2]
license_text = (root / "ci/ast-grep/rules/vendor/LICENSE").read_text()
readme = (root / "README.md").read_text()
assert "Apache License" in license_text
assert "Version 2.0, January 2004" in license_text
assert "ci/ast-grep/rules/vendor/LICENSE" in readme
print("ok   vendored ast-grep rules carry and disclose Apache-2.0")
