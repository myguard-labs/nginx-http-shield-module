#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/ci/linter"
cp "$root/ci/linter/lib.sh" "$root/ci/linter/lint-sh.sh" "$tmp/ci/linter/"
cat >"$tmp/probe.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
[ -n "${VALUE:-}" ] || { printf '%s\n' missing >&2; exit 2; }
SCRIPT

git -C "$tmp" init -q
git -C "$tmp" add -A

if (cd "$tmp" && LINT_MODE=all ci/linter/lint-sh.sh >lint.out 2>&1); then
    echo "unformatted shell probe unexpectedly passed" >&2
    exit 1
fi
grep -F 'probe.sh.orig' "$tmp/lint.out" >/dev/null

shfmt -i 4 -ci -w "$tmp/probe.sh"
(cd "$tmp" && LINT_MODE=all ci/linter/lint-sh.sh >/dev/null)
printf 'ok   shell formatter drift is causal and formatted input passes\n'
