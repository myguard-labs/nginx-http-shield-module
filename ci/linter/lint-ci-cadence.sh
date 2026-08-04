#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-cadence.sh -- a PR-gate workflow runs on the PR and nowhere
# else: no `push:` trigger, and no second `pull_request:` entry point of its own.
#
# The rule and the reasoning live in ci/linter/workflow_policy.py (subcommand
# `cadence`); this wrapper exists so run-all.sh picks the check up by glob and
# LINT_ONLY=ci-cadence selects it.
#
# The failure it prevents is invisible because BOTH runs are green. A member
# called by ci.yml can also carry `push: branches: [main]`, and `workflow_call`
# does not suppress it -- so every merge re-runs a gate against a commit
# identical to the PR head that already passed. The two runs use different
# concurrency keys, so cancel-in-progress does not collapse them either. Nothing
# fails; the repo just quietly pays for a second full build, and the merge
# cadence documented in README.md is no longer what the workflows do.
#
# Found by review on PR #101 (2026-08-04): six of the seven PR members carried
# the trigger. asan.yml was the only one already correct, which is exactly the
# shape this file exists for -- copying an existing workflow was the only thing
# standing between the repo and the regression, and nothing enforced the copy.
#
# Usage: ci/linter/lint-ci-cadence.sh [files...]   Env: LINT_MODE=staged|all
# Extend: `schedule` is deliberately allowed (codeql's periodic scan is not a
# merge gate). If a member ever needs its own trigger, document why in its
# header and add it to the check, not to the exceptions in your head.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '^\.github/workflows/.*\.ya?ml$' "$@")
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-ci-cadence: no workflow files to check"
    exit 0
}

need python3 "apt-get install python3"
# Whole-tree by nature: membership is derived from the pull_request entry
# point's job list, so a single changed file cannot be judged on its own.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" cadence
