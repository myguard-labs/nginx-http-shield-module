#!/usr/bin/env python3
"""Require one Semgrep version across local installation, hints, and CI."""

import re
from pathlib import Path

root = Path(__file__).parents[2]
files = [
    root / ".github/workflows/security-scanners.yml",
    root / ".github/workflows/ci-deep.yml",
    root / "ci/linter/install-linters.sh",
    root / "ci/linter/lint-c.sh",
]
versions = {}
for path in files:
    found = set(
        re.findall(
            r'(?:SEMGREP_VERSION:\s*"|semgrep==)([0-9]+(?:\.[0-9]+)+)',
            path.read_text(),
            re.IGNORECASE,
        )
    )
    assert len(found) == 1, (path, found)
    versions[path.name] = found.pop()
assert len(set(versions.values())) == 1, versions
print("ok   Semgrep pin aligned at " + next(iter(versions.values())))
