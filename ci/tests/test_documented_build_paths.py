#!/usr/bin/env python3
"""Keep documented build commands and mode-suffixed paths on the pinned nginx."""

import re
from pathlib import Path

root = Path(__file__).parents[2]
pins = (root / ".github/versions.env").read_text()
version = re.search(r"^NGINX_VERSION=([^\s]+)$", pins, re.MULTILINE).group(1)
readme = (root / "README.md").read_text()
prober = (root / "ci/t/prober/run.sh").read_text()
assert "nginx 1.31.3" not in readme
assert f".build/nginx-{version}-debug/objs/nginx" in readme
assert f".build/nginx-{version}-debug/objs/ngx_http_shield_module.so" in readme
assert f".build/nginx-{version}-debug/objs/nginx 120 4" in readme
assert f'VERSION="${{2:-{version}}}"' in prober
assert 'run.sh "$FLAVOR" "$VERSION"' in prober
print(f"ok   README build paths match pinned nginx {version} and debug mode")
