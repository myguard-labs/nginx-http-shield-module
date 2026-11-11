#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Real dispatch + index/worktree divergence controls; no fixture commit needed.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/stamp-gate-control.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/ci/linter" "$fixture/ci/tools" "$fixture/.github/workflows"
cp "$root/ci/linter/"{lib.sh,run-all.sh,lint-sync-stamp.sh} "$fixture/ci/linter/"
cp "$root/ci/tools/sync-stamp.sh" "$fixture/ci/tools/"
git -C "$fixture" init -q
cd "$fixture"
printf '# sync-sha: 0000000000000000000000000000000000000000000000000000000000000000\nname: fixture\n' >.github/workflows/p.yml
git add ci .github/workflows/p.yml
bash ci/tools/sync-stamp.sh >/dev/null

expect() {
    local want="$1" marker="$2"
    shift 2
    local got=0
    "$@" >"$fixture/result.log" 2>&1 || got=$?
    [ "$got" -eq "$want" ] || {
        cat "$fixture/result.log" >&2
        echo "stamp control: expected $want, got $got" >&2
        exit 1
    }
    grep -q "$marker" "$fixture/result.log" || {
        cat "$fixture/result.log" >&2
        echo "stamp control: missing expected marker $marker" >&2
        exit 1
    }
}

# Worktree is fresh; staged content is stale. A worktree-only checker lies here.
expect 1 'STALE stamp' env LINT_ONLY=sync-stamp ci/linter/run-all.sh --staged
git add .github/workflows/p.yml
expect 0 'all linters clean' env LINT_ONLY=sync-stamp ci/linter/run-all.sh --staged
printf '# sync-sha: 0000000000000000000000000000000000000000000000000000000000000000\nname: untracked\n' >.github/workflows/untracked.yml
expect 0 'all linters clean' env LINT_ONLY=sync-stamp ci/linter/run-all.sh --staged
printf '# sync-sha: 0000000000000000000000000000000000000000000000000000000000000000\nname: unrelated\n' >.github/workflows/other.yml
git add .github/workflows/other.yml
expect 0 'current' env LINT_MODE=all ci/linter/lint-sync-stamp.sh .github/workflows/p.yml
expect 1 'STALE stamp' env LINT_ONLY=sync-stamp ci/linter/run-all.sh --all
printf 'name: changed after staging\n' >>.github/workflows/p.yml
expect 0 'current' env LINT_MODE=staged ci/linter/lint-sync-stamp.sh .github/workflows/p.yml
expect 1 'STALE stamp' env LINT_MODE=all ci/linter/lint-sync-stamp.sh .github/workflows/p.yml
echo 'stamp gate: dispatch, failure propagation, staged bytes and selection passed'
