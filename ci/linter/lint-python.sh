#!/usr/bin/env bash
# ci/linter/lint-python.sh -- ruff lint + format check over tracked *.py.
#
# ruff replaces flake8/pyflakes/isort/black here: one binary, no venv, and it
# is what the superrepo's tools/ scripts are already checked with. The module
# tree carries no Python today; this gate exists so the first helper script
# committed under ci/tools/ is checked from its first commit instead of after
# it has grown.
#
# `ruff format --check` reports formatting WITHOUT rewriting: a linter that
# edits files behind a commit hook changes what you are about to commit.
#
# Usage: ci/linter/lint-python.sh [files...]   Env: LINT_MODE=staged|all
# Extend: per-rule config goes in a [tool.ruff] block in pyproject.toml at the
# repo root, not in flags here, so editors and CI see the same rules.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '\.py$' "$@")
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-python: no Python files to check"
    exit 0
}

echo "lint-python: ${#FILES[@]} file(s)"
need ruff "apt-get install ruff  (or: pipx install ruff)"
rc=0
say "ruff check"
ruff check "${FILES[@]}" || rc=1
say "ruff format --check"
ruff format --check "${FILES[@]}" || rc=1
exit "$rc"
