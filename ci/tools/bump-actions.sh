#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/bump-actions.sh -- move every `uses: owner/repo@<sha> # <tag>` pin in
# .github/ to the newest release of the tag's MAJOR line, rewriting both the sha
# and the trailing tag comment.
#
#   ci/tools/bump-actions.sh [--dry-run]
#
# WHY A SHA AND A COMMENT, AND WHY BOTH MUST MOVE TOGETHER
#
# A tag is mutable: whoever owns the action can repoint v5 at any commit, so a
# tag-pinned workflow runs whatever they push. The 40-char sha is the actual
# supply-chain control. But a bare sha is unreadable, so the convention is
# `@<sha> # v5` -- and that makes the comment a second copy of the truth. If a
# bump moves one and not the other, the file says v5 while running v4's code,
# and every later reader (including this script) trusts the lie. So the two are
# always rewritten as a unit, or not at all.
#
# MAJOR-LINE ONLY, ON PURPOSE
#
# v5 -> v6 is a breaking change by semver, and an unattended PR that silently
# crosses it turns a green CI into a debugging session nobody scheduled. This
# resolves the newest release WITHIN the pinned major (v5 -> newest v5.x) and
# reports a waiting major bump as a note for a human to do deliberately.
#
# Requires: gh (authenticated), git. Network: api.github.com.

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

cd "$(dirname "$0")/../.."

command -v gh >/dev/null || {
    echo "FATAL: gh not on PATH" >&2
    exit 1
}

CHANGED=0
NOTES=()
# Distinguishes "checked, nothing newer" from "could not check". Without this
# the two look identical in the log, and an expired token turns the weekly bump
# into a no-op that reports success every week -- the pins rot in place while
# the job stays green. Any failure to resolve a pin is fatal at the end.
FAILED=0

# One cache entry per repo: the same action is pinned in several workflows and
# each lookup is a rate-limited API call.
declare -A RESOLVED_SHA RESOLVED_TAG

# Collect every distinct owner/repo@sha # tag triple across .github/.
# `uses:` values may carry a subpath (github/codeql-action/init), which is NOT
# part of the repo for API purposes -- strip it to the first two segments.
mapfile -t PINS < <(
    grep -rhoE 'uses: [^ ]+@[0-9a-f]{40} # [^ ]+' .github/ |
        sed -E 's/^uses: //' | sort -u
)

if [ "${#PINS[@]}" -eq 0 ]; then
    echo "no sha-pinned actions found"
    echo "ACTIONS_CHANGED=0"
    exit 0
fi

for pin in "${PINS[@]}"; do
    ref="${pin%% # *}" # owner/repo[/sub]@sha
    tag="${pin##* # }" # v5
    path="${ref%@*}"   # owner/repo[/sub]
    sha="${ref##*@}"
    repo="$(printf '%s' "$path" | cut -d/ -f1,2)"

    major="$(printf '%s' "$tag" | sed -E 's/^v?([0-9]+).*/\1/')"
    if ! printf '%s' "$major" | grep -qE '^[0-9]+$'; then
        NOTES+=("skip $path: tag '$tag' has no numeric major")
        continue
    fi

    if [ -z "${RESOLVED_SHA[$repo]:-}" ]; then
        # Releases, newest first. --exclude-pre-releases keeps an -rc out of a
        # production pin. A release whose tag is not vN.* is not on this line.
        newest_in_major=""
        newest_any=""
        while read -r t; do
            [ -n "$t" ] || continue
            [ -n "$newest_any" ] || newest_any="$t"
            if printf '%s' "$t" | grep -qE "^v?${major}(\.|$)"; then
                newest_in_major="$t"
                break
            fi
        done < <(gh release list --repo "$repo" --limit 40 \
            --exclude-pre-releases --json tagName -q '.[].tagName' 2>/dev/null || true)

        if [ -z "$newest_in_major" ]; then
            NOTES+=("FAILED $repo: no release resolved on the v${major} line (auth? rate limit? renamed repo?)")
            FAILED=1
            RESOLVED_SHA[$repo]="-"
            RESOLVED_TAG[$repo]="-"
            continue
        fi

        # Resolve the tag to a COMMIT sha. A tag object's own sha is not the
        # commit; ^{} dereferences an annotated tag, which most actions use.
        # Getting this wrong pins a sha the runner cannot check out.
        new_sha="$(gh api "repos/$repo/git/ref/tags/$newest_in_major" \
            -q '.object.sha' 2>/dev/null || true)"
        obj_type="$(gh api "repos/$repo/git/ref/tags/$newest_in_major" \
            -q '.object.type' 2>/dev/null || true)"
        if [ "$obj_type" = "tag" ]; then
            new_sha="$(gh api "repos/$repo/git/tags/$new_sha" -q '.object.sha' 2>/dev/null || true)"
        fi
        if ! printf '%s' "$new_sha" | grep -qE '^[0-9a-f]{40}$'; then
            NOTES+=("FAILED $repo: could not resolve $newest_in_major to a commit sha")
            FAILED=1
            RESOLVED_SHA[$repo]="-"
            RESOLVED_TAG[$repo]="-"
            continue
        fi

        RESOLVED_SHA[$repo]="$new_sha"
        RESOLVED_TAG[$repo]="$newest_in_major"

        if [ -n "$newest_any" ] &&
            ! printf '%s' "$newest_any" | grep -qE "^v?${major}(\.|$)"; then
            NOTES+=("$repo: newer MAJOR available ($newest_any) -- bump by hand, it may break")
        fi
    fi

    new_sha="${RESOLVED_SHA[$repo]}"
    new_tag="${RESOLVED_TAG[$repo]}"
    [ "$new_sha" = "-" ] && continue
    [ "$new_sha" = "$sha" ] && continue

    echo "bump $path: ${sha:0:12} ($tag) -> ${new_sha:0:12} ($new_tag)"
    CHANGED=1
    [ "$DRY_RUN" = 1 ] && continue

    # Rewrite sha AND comment as one unit. Anchored on the exact old sha so a
    # second action pinned to a different sha in the same file is untouched.
    # `--` before the paths: a filename could otherwise be read as an option.
    while IFS= read -r f; do
        perl -pi -e "s{\Q$path\E\@\Q$sha\E # \Q$tag\E}{$path\@$new_sha # $new_tag}g" "$f"
    done < <(grep -rlF "$path@$sha" .github/ -- 2>/dev/null || grep -rlF "$path@$sha" .github/)
done

# The header comments in several workflows repeat the pin as documentation
# ("actions/checkout@v5 -> <sha>"). Those are the same second-copy hazard as the
# trailing tag comment, so keep them in step.
if [ "$DRY_RUN" = 0 ] && [ "$CHANGED" = 1 ]; then
    for repo in "${!RESOLVED_SHA[@]}"; do
        s="${RESOLVED_SHA[$repo]}"
        t="${RESOLVED_TAG[$repo]}"
        [ "$s" = "-" ] && continue
        # The comment spells the action the way `uses:` does -- owner/repo, and
        # for codeql-action a subpath too ("github/codeql-action/init@v4 -> ...").
        # Matching on the bare repo name silently updates nothing.
        #
        # The tag pattern must accept a FULL tag, not a bare major. The
        # replacement writes the resolved tag (v4.37.4), so a `@v?[0-9]+`
        # selector matches the file once and never again: the next bump moves
        # the `uses:` line (anchored on the sha) while the comment stays frozen
        # at the previous week's tag and sha. Verified by running two bumps
        # against a copy -- second pass selected zero files.
        grep -rlE "# ${repo}(/[A-Za-z0-9._-]+)?@v?[0-9][0-9A-Za-z._-]* +-> +[0-9a-f]{40}" .github/ 2>/dev/null |
            while IFS= read -r f; do
                perl -pi -e "s{(# \Q$repo\E(?:/[A-Za-z0-9._-]+)?\@)v?[0-9][0-9A-Za-z._-]*( +-> +)[0-9a-f]{40}}{\${1}$t\${2}$s}g" "$f"
            done
    done
fi

for n in "${NOTES[@]:-}"; do [ -n "$n" ] && echo "note: $n"; done

if [ "$FAILED" = 1 ]; then
    echo "FATAL: at least one action pin could not be checked -- refusing to" >&2
    echo "  report success. An unreachable API and an up-to-date pin must not" >&2
    echo "  look the same, or the weekly bump rots silently. Check gh auth." >&2
    echo "ACTIONS_CHANGED=$CHANGED"
    exit 1
fi

[ "$CHANGED" = 0 ] && echo "actions: every pin already newest on its major line"
echo "ACTIONS_CHANGED=$CHANGED"
