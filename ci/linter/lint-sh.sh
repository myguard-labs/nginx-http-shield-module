#!/usr/bin/env bash
# ci/linter/lint-sh.sh -- syntax, shellcheck, and shfmt over shell sources.
#
# For tracked *.sh files, bare severity (shellcheck's default, i.e. info and
# up) and shfmt's four-space/case-indent style match build-test.yml's
# "Validate scripts and source" step. The local gate additionally covers the
# extensionless pre-commit hook. The shared invocations must move together.
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
need shfmt "apt-get install shfmt"
for file in "${FILES[@]}"; do
    bash -n "$file"
done
shellcheck -x "${FILES[@]}"
shfmt -i 4 -ci -d "${FILES[@]}"
say "clean"
