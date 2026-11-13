#!/usr/bin/env bash
# ci/linter/lib.sh -- shared helpers for the ci/linter/lint-*.sh scripts.
#
# Sourced, never executed. Provides:
#   repo_root            absolute path of the checkout
#   lint_files <regex>   emit the file list to lint, one per line, NUL-safe
#                        callers use `mapfile -t`. Honours LINT_MODE:
#                          staged (default in the git hook) -- staged files only
#                          all                              -- every tracked file
#                        and an explicit file list passed in "$@" by run-all.sh.
#   lint_files_into <array-name> <regex> [explicit files...]
#                        checked array form; unlike process substitution, this
#                        preserves a failed git/file-discovery status.
#   need <tool> <hint>   hard-fail with an install hint when a linter is absent
#   drop_generated_vendor_rules
#                        remove generated upstream ast-grep YAML from a list
#   say / warn / die     consistent output
#
# Missing tools are a HARD FAILURE, never a silent skip: a gate that quietly
# disappears when its tool is uninstalled reports green while checking nothing.
# Run ci/linter/install-linters.sh to get them all.

set -euo pipefail

repo_root() { git rev-parse --show-toplevel; }

say() { printf '  %s\n' "$*"; }
warn() { printf '  WARN: %s\n' "$*" >&2; }
die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

need() {
    command -v "$1" >/dev/null 2>&1 && return 0
    die "$1 not found. Install it: $2   (or run ci/linter/install-linters.sh)"
}

# Paths never linted: byte-exact fuzz inputs, vendored trees, build output.
LINT_EXCLUDE_RE='^ci/fuzz/corpus/|^ci/fuzz/regressions/|^ci/vendor/|(^|/)objs/|(^|/)\.build/|(^|/)node_modules/|(^|/)\.venv/'

# lint_files <match-regex> [explicit files...]
lint_files() {
    local match_re="$1"
    shift
    local list
    if [ "$#" -gt 0 ]; then
        list=$(printf '%s\n' "$@")
    elif [ "${LINT_MODE:-all}" = "staged" ]; then
        list=$(git diff --cached --name-only --diff-filter=ACMR) || die "git diff --cached failed"
    else
        list=$(git ls-files) || die "git ls-files failed"
    fi
    printf '%s\n' "$list" |
        grep -Ev "$LINT_EXCLUDE_RE" |
        grep -E "$match_re" |
        while read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done ||
        true
}

lint_files_into() {
    local -n output="$1"
    shift
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/shield-lint-files.XXXXXX")" || die "mktemp failed"
    if ! lint_files "$@" >"$tmp"; then
        rm -f "$tmp"
        die "file discovery failed"
    fi
    # shellcheck disable=SC2034  # output is a nameref to the caller's array.
    mapfile -t output <"$tmp"
    rm -f "$tmp"
}

# These files are a byte-for-byte generated upstream snapshot. Their spelling
# and YAML style are not ours to fix, while rules/own remains first-party and
# must keep both checks. Call this only from those two prose/style linters;
# structural and provenance checks still need to see the generated snapshot.
drop_generated_vendor_rules() {
    grep -Ev '^ci/ast-grep/rules/vendor/' || true
}

drop_generated_vendor_files() {
    local -n files="$1"
    local kept=() file
    for file in "${files[@]}"; do
        [[ "$file" == ci/ast-grep/rules/vendor/* ]] || kept+=("$file")
    done
    files=("${kept[@]}")
}
