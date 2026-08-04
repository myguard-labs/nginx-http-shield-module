#!/usr/bin/env bash
# ci/linter/selftest.sh -- negative controls for the lint gate itself.
#
# The gate is the thing that decides whether everything else is allowed to
# land, so "the gate ran and said clean" has to be distinguishable from "the
# gate ran nothing and said clean". That distinction is not observable from a
# green lint job: a selector typo used to make run-all.sh print
# "== all linters clean ==" and exit 0 having executed zero checkers.
#
# Every case here asserts the FAILING direction -- a check that only ever
# asserts the passing direction cannot detect its own disarming.
#
# Usage:  ci/linter/selftest.sh
# Exit:   0 all controls held, 1 one or more did not.
#
# Runs in about a second: no case invokes a real checker (LINT_ONLY values are
# either bogus or rejected before dispatch), so no linter needs to be installed.
#
# Extend: add a case() line. Keep each case asserting a specific exit status,
# and prefer a case where the OLD, broken behaviour would have passed.

# shellcheck disable=SC2016
# File-scope on purpose. Nearly every case below hands a script to `bash -c`
# as a SINGLE-QUOTED heredoc-ish literal, and the whole point is that those
# `$root` / `$tmp` / `$1` expressions are expanded by the INNER shell, not by
# this one. SC2016 fires on each of them and is wrong in every case here.
#
# It is file-scope rather than per-case because a directive attached to one
# command does not cover a multi-line `bash -c '...'` argument consistently
# across shellcheck versions: 0.10 (local) accepted a single directive above
# the case, 0.9 (what build-test.yml installs on ubuntu-latest) still flagged
# lines inside the quoted body. A per-case directive therefore passes locally
# and fails in CI -- see lessons.md, the shellcheck severity/version entry.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

rc=0

# case <expected-exit> <description> -- command...
case_() {
    local want="$1" desc="$2"
    shift 2
    local out got
    out="$("$@" 2>&1)"
    got=$?
    if [ "$got" -eq "$want" ]; then
        echo "ok   $desc (exit $got)"
    else
        echo "FAIL $desc: expected exit $want, got $got" >&2
        while IFS= read -r outline; do
            printf '       | %s\n' "$outline" >&2
        done <<<"$out"
        rc=1
    fi
}

# The regression itself: an unmatched selector must be "could not run" (2),
# not "clean" (0).
case_ 2 "unknown LINT_ONLY exits 2" \
    env LINT_ONLY=nosuchchecker ci/linter/run-all.sh

# ...including when only SOME of the listed names are bogus in a way that
# leaves nothing selected.
case_ 2 "LINT_ONLY of only-bogus names exits 2" \
    env LINT_ONLY="c-lang shellscript" ci/linter/run-all.sh

# The error names the offending value and the known checkers, or nobody can
# act on it.
# Captured first, not piped into grep: `set -o pipefail` would otherwise hand
# the pipeline run-all.sh's exit 2 and the assertion would read as failed no
# matter what the message said.
msg="$(env LINT_ONLY=nosuchchecker ci/linter/run-all.sh 2>&1)"
if printf '%s\n' "$msg" | grep -q 'matched no checker; known: .*sh'; then
    echo "ok   unmatched-selector message names value and known checkers"
else
    echo "FAIL unmatched-selector message is not actionable" >&2
    rc=1
fi

# Positive control: the selector still selects. --list is used rather than a
# real run so this stays independent of which linters are installed.
case_ 0 "--list works" ci/linter/run-all.sh --list

# ----------------------------------------------------------------------------
# workflow_policy.py -- the red path of each policy check.
#
# Only `ports` and `docs` here, unlike the skeleton this was ported from: this
# repo's ci-runners checker is a thin wrapper around the EXISTING
# ci/tools/check-workflow-runners.sh (see ci/linter/lint-ci-runners.sh), not a
# port of workflow_policy.py's `runners` subcommand -- which does not exist in
# this copy. That tool's own red path is exercised in the WIRING CONTROLS
# section below, and the "typo'd LINT_ONLY" case at the top of this file
# already covers the same gate-cannot-silently-disappear property.
#
# Every fixture below encodes a bypass that VALID YAML used to walk straight
# through while the checks parsed workflows by regex. Each was verified in both
# directions when it was written: red on the current parser, green on the
# regex one. They are committed rather than planted in .github/workflows/ at
# runtime so no cleanup failure can leave a probe workflow in the live tree.
#
# Extend: add a fixture directory with its own .github/workflows/ and a README
# stating which bypass it encodes, then a policy_ line here.

policy_() { # policy_ <expected-exit> <fixture> <subcommand>
    local want="$1" fixture="$2" cmd="$3"
    case_ "$want" "policy $cmd: $fixture" \
        env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd"
}

# THE control that makes the rest mean anything: a fixture tree that is simply
# a valid workflow must be GREEN on both. Without it, a red on any bypass
# fixture could be the fixture shape rather than the bypass.
policy_ 0 clean ports
policy_ 0 clean docs
# `cadence` derives membership from the entry point's job list, so it needs a
# fixture whose ci.yml actually CALLS something -- the `clean` tree has no
# members and correctly refuses to run (exit 2) rather than reporting clean.
policy_ 0 cadence-clean cadence

# A workflow_call member that ALSO fires on `push: main`, and one that declares
# a second `pull_request` entry point. Both are green in real CI, which is why
# only a structural check finds them. Six of shield's seven members carried the
# first shape until 2026-08-04.
policy_ 1 member-reruns-on-push cadence

# A `.yaml` workflow was invisible to every check: undocumented gate.
policy_ 1 bypass-yaml-extension docs

# `runtime:  # comment` used to yield zero jobs, so a runtime-bearing job with
# no port band reported "no runtime-bearing jobs" and exit 0.
policy_ 1 bypass-commented-job-key ports

# A band verifier placed BELOW the first binder. Declaration, pass-through and
# uniqueness all hold, so the presence checks stay green -- the skeleton this
# was ported from shipped this exact shape until 2026-08-02.
policy_ 1 verify-after-bind ports

# WIRING CONTROLS. These assert that a checker is reachable at all, which is a
# weaker claim than "it goes red on a defect" -- the red-direction probes need
# real tools and live in each checker's header instead, so this file keeps its
# no-linter-required property. They exist because a checker nobody dispatches
# looks exactly like a clean tree.
#
# lint-ci-runners.sh is a thin wrapper around ci/tools/check-workflow-runners.sh
# (see that script's header for the runner-trust rule and reasoning). This
# asserts the WIRING -- that the wrapper actually calls through and forwards a
# non-zero exit -- not the trust-boundary logic itself, which is
# check-workflow-runners.sh's own concern and not re-tested here.
case_ 1 "lint-ci-runners forwards a failing check-workflow-runners.sh" \
    bash -c '
        set -e
        root="$1"
        tmp="$(mktemp -d)"
        trap "rm -rf \"$tmp\"" EXIT
        mkdir -p "$tmp/ci/tools"
        printf "#!/bin/sh\nexit 1\n" > "$tmp/ci/tools/check-workflow-runners.sh"
        chmod +x "$tmp/ci/tools/check-workflow-runners.sh"
        mkdir -p "$tmp/.github/workflows" "$tmp/ci/linter"
        printf "name: p\non: {pull_request: {}}\njobs: {p: {runs-on: ubuntu-latest, steps: [{run: echo hi}]}}\n" \
            > "$tmp/.github/workflows/p.yml"
        cp "$root/ci/linter/lib.sh" "$tmp/ci/linter/lib.sh"
        cp "$root/ci/linter/lint-ci-runners.sh" "$tmp/ci/linter/lint-ci-runners.sh"
        # -c overrides keep the fixture self-contained: a CI runner has no
        # global user.identity (git exits 128), and a dev box may have
        # commit.gpgsign=true with no key available here.
        cd "$tmp" && git init -q && git add -A &&
            git -c user.name=lint -c user.email=lint@invalid -c commit.gpgsign=false \
                commit -q -m x --no-verify
        LINT_MODE=all ci/linter/lint-ci-runners.sh
    ' _ "$ROOT"

# run-all.sh dispatches by glob, so a checker that is not executable, or is
# named outside the lint-*.sh pattern, is silently not run.
case_ 0 "lint-spelling is dispatched by run-all.sh" \
    bash -c 'ci/linter/run-all.sh --list | grep -q lint-spelling.sh'
case_ 0 "lint-ci-runners is dispatched by run-all.sh" \
    bash -c 'ci/linter/run-all.sh --list | grep -q lint-ci-runners.sh'

# Unparsable YAML is "could not run" (2), never "clean" -- GitHub may still
# read a file this parser rejects, so a verdict over the rest of the tree would
# be unsupported. Fixture is generated: a committed broken-YAML file would trip
# yamllint on the real tree.
badroot="$(mktemp -d)"
trap 'rm -rf "$badroot"' EXIT
mkdir -p "$badroot/.github/workflows"
printf 'on: [pull_request\njobs: {\n' >"$badroot/.github/workflows/broken.yml"
case_ 2 "policy ports: unparsable YAML is exit 2, not clean" \
    env "WORKFLOW_POLICY_ROOT=$badroot" python3 ci/linter/workflow_policy.py ports

if [ "$rc" -eq 0 ]; then
    echo "== lint gate selftest: all controls held =="
else
    echo "== lint gate selftest: FAILED ==" >&2
fi
exit "$rc"
