#!/usr/bin/env python3
"""Positive and negative controls for directive documentation drift."""

import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[2]
checker = root / "ci/linter/check-directive-docs.py"
source = root / "src/ngx_http_shield_module.c"
readme = (root / "README.md").read_text()
subprocess.run([checker, source, root / "README.md"], check=True)
with tempfile.TemporaryDirectory() as directory:
    fixture = Path(directory) / "README.md"
    fixture.write_text(readme.replace("| `shield_gzip` |", "| `removed_gzip` |", 1))
    result = subprocess.run(
        [checker, source, fixture], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert "shield_gzip" in result.stderr and "removed_gzip" not in result.stderr
print("ok   directive docs checker accepts parity and rejects a removed row")
