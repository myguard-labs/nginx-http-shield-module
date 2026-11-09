#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/ci/tools" "$tmp/.github/scripts"
cp "$root/ci/tools/bump-versions.sh" "$tmp/ci/tools/"
printf 'same\n' >"$tmp/.github/versions.env"
cat >"$tmp/.github/scripts/compute-versions.sh" <<'SCRIPT'
printf 'same\n' > .github/versions.env
SCRIPT
cat >"$tmp/ci/tools/bump-actions.sh" <<'SCRIPT'
printf 'ACTIONS_CHANGED=%s\n' "${ACTIONS_CHANGED:-0}"
exit "${ACTIONS_EXIT:-0}"
SCRIPT
cat >"$tmp/ci/tools/bump-tools.sh" <<'SCRIPT'
printf 'TOOLS_CHANGED=%s\n' "${TOOLS_CHANGED:-0}"
exit "${TOOLS_EXIT:-0}"
SCRIPT

run_case() {
    local expected_exit="$1" expected_output="$2"
    shift 2
    local rc=0
    (cd "$tmp" && env "$@" bash ci/tools/bump-versions.sh --dry-run) >"$tmp/output" 2>&1 || rc=$?
    if [ "$rc" -ne "$expected_exit" ] || ! grep -qxF "$expected_output" "$tmp/output"; then
        cat "$tmp/output"
        printf 'expected exit %s and %s, got exit %s\n' "$expected_exit" "$expected_output" "$rc" >&2
        exit 1
    fi
}
run_case 0 CHANGED=0
run_case 0 CHANGED=1 ACTIONS_CHANGED=1
run_case 0 CHANGED=1 TOOLS_CHANGED=1
run_case 17 ACTIONS_CHANGED=0 ACTIONS_EXIT=17
run_case 19 TOOLS_CHANGED=0 TOOLS_EXIT=19
printf 'ok   dry-run propagates child failures and change markers\n'
