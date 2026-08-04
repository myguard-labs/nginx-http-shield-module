#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-runners.sh -- fork PRs must never select the self-hosted
# runner, mapped onto this repo's EXISTING trust-boundary check.
#
# Unlike the skeleton, this is not a port of workflow_policy.py's `runners`
# subcommand. shield already has ci/tools/check-workflow-runners.sh, which
# enforces exactly the property this checker is for -- every pull_request-
# reachable workflow stays on a GitHub-hosted runner -- against this repo's
# ACTUAL trust split (push/schedule/dispatch on self-hosted, PR-time on
# ubuntu-latest; see build-test.yml, ci-deep.yml, bump.yml). Porting the
# skeleton's TRUST_SPLITS/label-membership logic instead would encode the
# SKELETON's runner-pool inventory, not shield's, and give two competing
# sources of truth for the same boundary. So this script is a THIN WRAPPER:
# it calls the existing tool and maps its exit status into the linter
# contract (0 clean / 1 findings / 2 tool missing), same as every other
# ci/linter/lint-*.sh here.
#
# check-workflow-runners.sh already prints the offending workflow(s) on
# failure, so this wrapper adds no extra text -- doing so would just be a
# second, possibly-drifting copy of the same message.
#
# Usage: ci/linter/lint-ci-runners.sh [files...]   Env: LINT_MODE=staged|all
# Extend: the trust-boundary RULE lives in ci/tools/check-workflow-runners.sh.
# A new self-hosted label or workflow needs no change here -- this wrapper
# only forwards the tool's verdict.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '^\.github/workflows/.*\.ya?ml$' "$@")
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-ci-runners: no workflow files to check"
    exit 0
}

ROOT="$(git rev-parse --show-toplevel)"
TOOL="$ROOT/ci/tools/check-workflow-runners.sh"
if [ ! -x "$TOOL" ]; then
    die "$TOOL missing or not executable -- it ships in this repo; check it out"
fi

echo "lint-ci-runners: delegating to ci/tools/check-workflow-runners.sh"
exec "$TOOL"
