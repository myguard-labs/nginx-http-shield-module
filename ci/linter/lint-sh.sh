#!/usr/bin/env bash
# ci/linter/lint-sh.sh -- shellcheck over every *.sh / *.bash in the tree.
#
# Bare severity (shellcheck's default, i.e. info and up), matching exactly
# what build-test.yml's "Validate scripts and source" step runs remotely
# (bare `shellcheck "$s"`, no -S). This gate exists to PREDICT that remote
# gate, so the two invocations must move together: an info-level finding
# invisible here but fatal there is the exact mismatch that turned PR #91 red
# twice. If build-test.yml's severity or -x usage ever changes, change this
# script in the same commit -- never let them drift apart again.
#
# Usage: ci/linter/lint-sh.sh [files...]   Env: LINT_MODE=staged|all

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# .githooks/* has no extension but is bash; an unchecked commit hook is the
# one script whose bug silently disables every other check here.
mapfile -t FILES < <(lint_files '\.(sh|bash)$|^\.githooks/' "$@")
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-sh: no shell files to check"
    exit 0
}

echo "lint-sh: ${#FILES[@]} file(s)"
need shellcheck "apt-get install shellcheck"
shellcheck -x "${FILES[@]}"
say "clean"
