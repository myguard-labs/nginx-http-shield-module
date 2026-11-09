#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail
root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/src"
cat >"$tmp/bin/flawfinder" <<'MOCK'
#!/usr/bin/env bash
if [[ "$*" == *--minlevel=4* ]]; then
    printf '%s\n' "${MOCK_REPORT:-Hits = 0}"
    exit "${MOCK_STATUS:-0}"
fi
exit "${MOCK_FIRST_STATUS:-0}"
MOCK
chmod +x "$tmp/bin/flawfinder"
cd "$tmp"
export GITHUB_WORKSPACE="$tmp" PATH="$tmp/bin:$PATH"
bash "$root/ci/tools/flawfinder-gate.sh" >/dev/null
if MOCK_REPORT='Hits = 1' bash "$root/ci/tools/flawfinder-gate.sh" >/dev/null 2>&1; then
    echo 'high severity findings were swallowed' >&2
    exit 1
fi
if MOCK_STATUS=42 bash "$root/ci/tools/flawfinder-gate.sh" >/dev/null 2>&1; then
    echo 'second scanner failure was swallowed' >&2
    exit 1
fi
if MOCK_FIRST_STATUS=42 bash "$root/ci/tools/flawfinder-gate.sh" >/dev/null 2>&1; then
    echo 'first scanner failure was swallowed' >&2
    exit 1
fi
echo 'flawfinder gate controls passed'
