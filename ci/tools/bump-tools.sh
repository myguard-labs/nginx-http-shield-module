#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/bump-tools.sh -- move the pinned PyPI linter versions to their newest
# release, in EVERY file that names them.
#
#   ci/tools/bump-tools.sh [--dry-run]
#
# WHY THIS IS NOT A ONE-LINE sed
#
# The semgrep pin appears as a workflow `env:` in two files that must agree:
# .github/workflows/security-scanners.yml (the PR-time scanner gate) and
# .github/workflows/ci-deep.yml (the monthly/dispatch exhaustive run). They
# are pinned to the same version ON PURPOSE -- the whole point of the pin is
# that both gates scan with the identical tool. Bumping one and missing the
# other does not fail loudly; it just means the two jobs quietly disagree
# about what "clean" means, which is the exact failure the pin exists to
# prevent. So this rewrites every occurrence repo-wide and asserts afterwards
# that one version is left.
#
# Unlike the skeleton module this was ported from, shield has no
# ci/linter/install-linters.sh or ci/linter/lint-c.sh (there is no ci/linter/
# directory at all) and no ruff pin anywhere -- both were dropped from TOOLS[]
# below rather than left as a sed that silently matches nothing.
#
# Requires: curl, python3. Network: pypi.org.

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

cd "$(dirname "$0")/../.."

CHANGED=0
# See bump-actions.sh: "could not check" must never be reported as "up to
# date", or an outage/rename leaves the pins rotting behind a green job.
FAILED=0

# Package name -> the files allowed to carry its pin. Listing them rather than
# globbing keeps a stray match in a .md or a lockfile from being rewritten.
TOOLS=(
    "semgrep:.github/workflows/security-scanners.yml .github/workflows/ci-deep.yml"
)

newest_on_pypi() {
    # /json returns every release; info.version is the newest NON-prerelease,
    # which is what a CI pin wants. Fail loudly rather than emit an empty
    # string that a later sed would happily write into the file.
    local pkg="$1" body
    body="$(curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 60 \
        "https://pypi.org/pypi/${pkg}/json")" || return 1
    printf '%s' "$body" | python3 -c '
import json,sys
v = json.load(sys.stdin)["info"]["version"]
if not v:
    sys.exit(1)
print(v)
'
}

for entry in "${TOOLS[@]}"; do
    pkg="${entry%%:*}"
    files="${entry#*:}"

    # Current pin, read from the first file that has one. All files are asserted
    # to agree at the end, so any of them is a valid source of truth here.
    # The pin here is a workflow env var (SEMGREP_VERSION: "1.169.0"), not a
    # bare `pkg==ver` literal, so match the quoted version string.
    cur=""
    for f in $files; do
        [ -f "$f" ] || continue
        cur="$(grep -hoE "SEMGREP_VERSION: \"[0-9]+(\.[0-9]+)*\"" "$f" | head -1 |
            sed -E 's/.*"([0-9.]+)"/\1/' || true)"
        [ -n "$cur" ] && break
    done
    if [ -z "$cur" ]; then
        echo "FAILED ${pkg}: no SEMGREP_VERSION pin found in any of its listed files" >&2
        FAILED=1
        continue
    fi

    if ! new="$(newest_on_pypi "$pkg")"; then
        echo "FAILED ${pkg}: could not reach pypi.org, ${cur} left alone" >&2
        FAILED=1
        continue
    fi

    if [ "$new" = "$cur" ]; then
        echo "${pkg}: already newest (${cur})"
        continue
    fi

    echo "bump ${pkg}: ${cur} -> ${new}"
    CHANGED=1
    [ "$DRY_RUN" = 1 ] && continue

    for f in $files; do
        [ -f "$f" ] || continue
        perl -pi -e "s{SEMGREP_VERSION: \"\Q${cur}\E\"}{SEMGREP_VERSION: \"${new}\"}g" "$f"
    done

    # The sync IS the feature -- assert it rather than assume the loop above
    # covered every copy. A pin that reappears somewhere unlisted must fail the
    # bump, not ship a split-brain version.
    #
    # ci/tools/bump-{tools,actions,versions}.sh are excluded because they are
    # ABOUT pins: any version literal in them is prose in a comment, not a pin
    # to keep in step.
    stray="$(grep -rhoE "SEMGREP_VERSION: \"[0-9]+(\.[0-9]+)*\"" \
        --include='*.yml' --include='*.yaml' --include='*.sh' \
        --exclude='bump-tools.sh' --exclude='bump-actions.sh' \
        --exclude='bump-versions.sh' \
        .github ci 2>/dev/null | sort -u | grep -v "\"${new}\"\$" || true)"
    if [ -n "$stray" ]; then
        echo "FATAL: ${pkg} pins disagree after bump:" >&2
        printf '  %s\n' "$stray" >&2
        echo "  add the file holding it to TOOLS[] in $0" >&2
        exit 1
    fi
done

if [ "$FAILED" = 1 ]; then
    echo "FATAL: at least one tool pin could not be checked -- refusing to" >&2
    echo "  report success (see bump-actions.sh for why)." >&2
    echo "TOOLS_CHANGED=$CHANGED"
    exit 1
fi

[ "$CHANGED" = 0 ] && echo "tools: every pin already newest"
echo "TOOLS_CHANGED=$CHANGED"
