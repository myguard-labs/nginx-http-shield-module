#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Check the selected CI files, using index bytes in hook mode. Snapshotting
# keeps unrelated/untracked working-tree files out of this selected-file gate.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

root="$(repo_root)"
cd "$root" || exit
snapshot="$(mktemp -d "${TMPDIR:-/tmp}/lint-sync-stamp.XXXXXX")"
trap 'rm -rf -- "$snapshot"' EXIT

# The shared selector filters by worktree existence. In index mode a staged
# file must be checked even if an unstaged deletion removed its worktree copy.
FILES=()
if [ "${LINT_MODE:-all}" = staged ]; then
    if [ "$#" -gt 0 ]; then
        printf '%s\0' "$@" >"$snapshot/paths"
    else
        git diff --cached --name-only --diff-filter=ACMR -z >"$snapshot/paths"
    fi
    mapfile -t -d '' CANDIDATES <"$snapshot/paths"
    for file in "${CANDIDATES[@]}"; do
        case "$file" in .github/*) FILES+=("$file") ;; esac
    done
else
    mapfile -t FILES < <(lint_files '^\.github/' "$@")
fi
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-sync-stamp: no CI content changes"
    exit 0
}

mkdir -p "$snapshot/.github/workflows" "$snapshot/ci/tools"
if [ "${LINT_MODE:-all}" = staged ]; then
    git show :ci/tools/sync-stamp.sh >"$snapshot/ci/tools/sync-stamp.sh"
else
    cp "$root/ci/tools/sync-stamp.sh" "$snapshot/ci/tools/sync-stamp.sh"
fi
for file in "${FILES[@]}"; do
    case "$file" in
        *'/../'* | *$'\n'*) die "unsafe CI path" ;;
        .github/*) ;;
        *) die "expected a repository-relative CI path" ;;
    esac
    mkdir -p "$(dirname "$snapshot/$file")"
    if [ "${LINT_MODE:-all}" = staged ]; then
        entry="$(git ls-files --stage -- "$file")"
        case "${entry%% *}" in
            100644 | 100755) ;;
            *) die "CI stamp input must be an indexed regular file: $file" ;;
        esac
        git show ":$file" >"$snapshot/$file"
    else
        resolved="$(realpath -e -- "$file")"
        case "$resolved" in
            "$root"/.github/*) ;;
            *) die "CI stamp input escapes the project: $file" ;;
        esac
        [ ! -L "$file" ] || die "CI stamp input must not be a symlink: $file"
        cp -- "$file" "$snapshot/$file"
    fi
done
(cd "$snapshot" && bash ci/tools/sync-stamp.sh --check-tree "$snapshot")
