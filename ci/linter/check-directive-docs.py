#!/usr/bin/env python3
"""Keep production Shield directives and the README reference table aligned."""

import re
import sys
from pathlib import Path

source = Path(sys.argv[1] if len(sys.argv) > 1 else "src/ngx_http_shield_module.c")
readme = Path(sys.argv[2] if len(sys.argv) > 2 else "README.md")
registered = set(
    re.findall(r'ngx_string\("(shield_[a-z_]+|shield)"\)', source.read_text())
)
registered.discard("shield_probe")
documented = set(
    re.findall(r"^\| `(shield_[a-z_]+|shield)` \|", readme.read_text(), re.MULTILINE)
)
missing = sorted(registered - documented)
stale = sorted(documented - registered)
if missing or stale:
    if missing:
        print("undocumented directives: " + ", ".join(missing), file=sys.stderr)
    if stale:
        print("stale directive rows: " + ", ".join(stale), file=sys.stderr)
    raise SystemExit(1)
print(f"directive docs: {len(registered)} production directives documented")
