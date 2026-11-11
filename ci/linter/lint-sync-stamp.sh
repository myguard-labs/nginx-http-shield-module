#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Check the CI content stamps before commit, as lint.yml does before its gates.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '^\.github/' "$@")
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-sync-stamp: no CI content changes"
    exit 0
}

exec bash "$(git rev-parse --show-toplevel)/ci/tools/sync-stamp.sh" --check
