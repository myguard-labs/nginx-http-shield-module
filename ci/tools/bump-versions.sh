#!/usr/bin/env bash
#
# Refresh every upstream pin in this repo. Called by .github/workflows/bump.yml
# on a schedule; also runnable locally to preview a bump before it lands.
#
#   ci/tools/bump-versions.sh [--dry-run]
#
# Three things move here:
#   - .github/versions.env            -- nginx mainline/stable + angie versions
#                                        AND their sha256s, rewritten wholesale
#                                        by .github/scripts/compute-versions.sh
#   - GitHub Action sha pins          -- ci/tools/bump-actions.sh (sha + the tag
#                                        comment beside it, as one unit)
#   - pinned linter versions          -- ci/tools/bump-tools.sh (semgrep;
#                                        every copy of the pin, kept in sync)
#
# Unlike the skeleton module this was ported from, this repo has no
# ci/vendor/nginx-tests submodule to pull -- shield's only real submodule is
# ci/t/harness, which is NOT a vendored upstream test corpus and must not be
# bumped by this script. There is nothing to do here for it.
#
# versions.env used to say "no bump workflow wired up yet in this module" --
# that sentence predates this script; it is now stale and has been removed
# (see .github/scripts/compute-versions.sh, which regenerates the same header).
#
# --dry-run reports what WOULD change without writing anything: versions.env is
# regenerated into a scratch copy and diffed.
#
# Exit status is 0 whether or not anything changed; the caller decides what to
# do with a dirty tree. Prints CHANGED=0|1 as its last line.
#
# GH_TOKEN is honoured (passed through to compute-versions.sh as GITHUB_TOKEN):
# the runners share an egress IP, so unauthenticated api.github.com calls are
# routinely rate-limited to 403s.

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

cd "$(dirname "$0")/../.."

# compute-versions.sh reads GITHUB_TOKEN; bump.yml historically set GH_TOKEN.
export GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

CHANGED=0
VERSIONS_FILE=".github/versions.env"

# --- version + sha256 pins -------------------------------------------------
if [ "$DRY_RUN" = 0 ]; then
    # Tolerate a missing file: compute-versions.sh creates it from scratch, so
    # bootstrapping (or regenerating after a delete) should report "changed"
    # rather than dying here under set -e.
    before="$(cat "$VERSIONS_FILE" 2>/dev/null || true)"
    bash .github/scripts/compute-versions.sh
    if [ "$before" != "$(cat "$VERSIONS_FILE")" ]; then
        echo "--- versions.env changed ---"
        git --no-pager diff -- "$VERSIONS_FILE" || true
        CHANGED=1
    else
        echo "versions.env already up to date"
    fi
else
    # Regenerate into a scratch copy so the working tree is untouched.
    scratch="$(mktemp -d)"
    trap 'rm -rf "$scratch"' EXIT
    cp -a .github "$scratch/.github"
    (cd "$scratch" && bash .github/scripts/compute-versions.sh >/dev/null)
    if diff -u "$VERSIONS_FILE" "$scratch/$VERSIONS_FILE"; then
        echo "(dry-run: versions.env already up to date)"
    else
        echo "(dry-run: versions.env would change as shown above)"
        CHANGED=1
    fi
fi

# --- GitHub Action pins ----------------------------------------------------
# Actions are already sha-pinned; what was missing was anything that MOVES the
# pin. An unmaintained sha is not "stable", it is a frozen copy of an action
# that stopped receiving its own security fixes. Major-line only -- see
# bump-actions.sh for why crossing a major unattended is not wanted.
## In --dry-run the children write nothing, so `git diff --quiet` always sees a
# clean tree and CHANGED stays 0 even when the child just printed pending
# bumps -- a dry-run that contradicts its own output. Both children already
# emit a machine-readable ACTIONS_CHANGED=0|1 / TOOLS_CHANGED=0|1 marker as
# their last line for exactly this purpose: read it instead of trusting the
# working tree. `tee` keeps the child's full output streaming to the user
# while a copy is captured to grep the marker from; PIPESTATUS preserves the
# child's real exit code past the pipe.
if [ "$DRY_RUN" = 0 ]; then
    bash ci/tools/bump-actions.sh
    if ! git diff --quiet -- .github/ 2>/dev/null; then
        CHANGED=1
    fi
else
    actions_out="$(mktemp)"
    bash ci/tools/bump-actions.sh --dry-run | tee "$actions_out" || true
    rc="${PIPESTATUS[0]}"
    if [ "$rc" != 0 ]; then
        rm -f "$actions_out"
        exit "$rc"
    fi
    if grep -qE '^ACTIONS_CHANGED=1$' "$actions_out"; then
        CHANGED=1
    fi
    rm -f "$actions_out"
fi

# --- pinned linter versions ------------------------------------------------
# semgrep is pinned so the pin cannot silently change what the gate scans
# with; bump-tools.sh keeps every copy of the pin in step and fails if one is
# left behind.
if [ "$DRY_RUN" = 0 ]; then
    bash ci/tools/bump-tools.sh
    if ! git diff --quiet -- .github/ ci/ 2>/dev/null; then
        CHANGED=1
    fi
else
    tools_out="$(mktemp)"
    bash ci/tools/bump-tools.sh --dry-run | tee "$tools_out" || true
    rc="${PIPESTATUS[0]}"
    [ "$rc" = 0 ] || {
        rm -f "$tools_out"
        exit "$rc"
    }
    if grep -qE '^TOOLS_CHANGED=1$' "$tools_out"; then
        CHANGED=1
    fi
    rm -f "$tools_out"
fi

if [ "$CHANGED" = 0 ]; then
    echo "everything up to date, nothing to bump"
fi

echo "CHANGED=$CHANGED"
