#!/usr/bin/env bash
# sync-sha: c4d2bd046b87ff88648b8d92b13d769b0028bdc440e88858e6fe571db74c4f13
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# load-versions.sh -- export every pin from .github/versions.env into the
# workflow environment. Run as the first step of every CI job:
#
#   - run: bash .github/scripts/load-versions.sh
#
# Skips comments/blanks; validates each line is KEY=value so a malformed
# versions.env fails loudly instead of injecting garbage into $GITHUB_ENV.
set -euo pipefail

f=".github/versions.env"
[ -f "$f" ] || {
    echo "::error::$f not found" >&2
    exit 1
}
# Outside a GitHub Actions step $GITHUB_ENV is unset, and set -u turns that
# into a bare "unbound variable" -- give anyone running this by hand a
# message that says what actually went wrong.
[ -n "${GITHUB_ENV:-}" ] || {
    echo "::error::GITHUB_ENV unset -- run this inside a GitHub Actions step" >&2
    exit 1
}

while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        '' | \#*) continue ;;
    esac
    if ! printf '%s' "$line" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*='; then
        echo "::error::malformed line in $f: $line" >&2
        exit 1
    fi
    echo "$line" >>"$GITHUB_ENV"
    echo "loaded: ${line%%=*}"
done <"$f"
