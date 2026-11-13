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
# The Semgrep pin appears as a workflow `env:` in two files and as a direct
# `semgrep==` requirement in the local installer and lint hint. All four must
# agree or local and remote checks use different rule sets. This rewrites both
# forms and asserts that no stale pin remains, including when PyPI already
# reports the listed version as newest.
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
    "semgrep:.github/workflows/security-scanners.yml .github/workflows/ci-deep.yml ci/linter/install-linters.sh ci/linter/lint-c.sh"
)

pin_versions() {
    grep -hoE 'SEMGREP_VERSION: "[0-9]+(\.[0-9]+)*"|semgrep==[0-9]+(\.[0-9]+)*' "$@" |
        sed -E 's/.*(SEMGREP_VERSION: "|semgrep==)([0-9]+(\.[0-9]+)*).*/\2/' |
        sort -u
}

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

    # Every listed file must exist -- a missing file is silently "no pin to
    # disagree" if skipped, and a rename/typo in TOOLS[] would rot unnoticed.
    for f in $files; do
        if [ ! -f "$f" ]; then
            echo "FAILED ${pkg}: listed file '${f}' does not exist" >&2
            FAILED=1
            continue 2
        fi
    done

    # Collect the pin from EVERY listed file BEFORE any up-to-date shortcut.
    # Reading only the first file lets a later stale pin hide behind an early
    # exit. Each listed file must contain exactly one version.
    cur=""
    disagree=0
    for f in $files; do
        v="$(pin_versions "$f" || true)"
        if [ -z "$v" ]; then
            echo "FAILED ${pkg}: no pin found in listed file '${f}'" >&2
            FAILED=1
            continue 2
        fi
        if [ "$(printf '%s\n' "$v" | wc -l)" -ne 1 ]; then
            disagree=1
            continue
        fi
        if [ -z "$cur" ]; then
            cur="$v"
        elif [ "$v" != "$cur" ]; then
            disagree=1
        fi
    done
    if [ -z "$cur" ]; then
        echo "FAILED ${pkg}: no pin found in its listed files" >&2
        FAILED=1
        continue
    fi
    if [ "$disagree" = 1 ]; then
        echo "FATAL: ${pkg} pins disagree across its listed files BEFORE any bump:" >&2
        for f in $files; do
            v="$(pin_versions "$f" || true)"
            [ -n "$v" ] && echo "  $f: $v" >&2
        done
        exit 1
    fi

    if ! new="$(newest_on_pypi "$pkg")"; then
        echo "FAILED ${pkg}: could not reach pypi.org, ${cur} left alone" >&2
        FAILED=1
        continue
    fi

    if [ "$new" = "$cur" ]; then
        echo "${pkg}: already newest (${cur})"
    else
        echo "bump ${pkg}: ${cur} -> ${new}"
        CHANGED=1
        if [ "$DRY_RUN" = 0 ]; then
            for f in $files; do
                perl -pi -e \
                    "s{SEMGREP_VERSION: \"\Q${cur}\E\"}{SEMGREP_VERSION: \"${new}\"}g; s{semgrep==\Q${cur}\E}{semgrep==${new}}g" \
                    "$f"
            done
        fi
    fi

    [ "$DRY_RUN" = 1 ] && continue

    # The sync IS the feature -- assert it rather than assume the loop above
    # covered every copy. A pin that reappears somewhere unlisted must fail the
    # bump, not ship a split-brain version.
    #
    # ci/tools/bump-{tools,actions,versions}.sh are excluded because they are
    # ABOUT pins: any version literal in them is prose in a comment, not a pin
    # to keep in step.
    stray="$(grep -rhoE 'SEMGREP_VERSION: "[0-9]+(\.[0-9]+)*"|semgrep==[0-9]+(\.[0-9]+)*' \
        --include='*.yml' --include='*.yaml' --include='*.sh' \
        --exclude='bump-tools.sh' --exclude='bump-actions.sh' \
        --exclude='bump-versions.sh' \
        .github ci 2>/dev/null | pin_versions /dev/stdin | grep -vx "${new}" || true)"
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
