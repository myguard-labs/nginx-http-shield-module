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

# One cache entry per repo@major: the same action is pinned in several
# workflows and each lookup is a rate-limited API call. Keying by repo alone
# would let a repo pinned on two major lines (e.g. v3 in one workflow, v4 in
# another) reuse the FIRST pin's resolution for the second, silently moving
# the v3 pin onto the v4 line. Latent today (every shield-pinned repo sits on
# exactly one major) but fires the moment that stops being true.
declare -A RESOLVED_SHA RESOLVED_TAG

# A selected-actions policy may allow a third-party action by its exact commit
# SHA.  In that case changing only the workflow pin makes GitHub reject the
# whole workflow before it can create a job (the API reports
# `startup_failure`, with no logs).  Keep the current allowed pin until the
# candidate SHA has also been admitted at both the repository and organization
# levels.  This is deliberately narrower than trying to reimplement all of
# GitHub's pattern matching: an exact current-SHA entry is the predicate that
# can be invalidated by this script, while wildcards and verified/GitHub-owned
# allowances continue to cover every SHA of the same action.
POLICY_REPO="${GITHUB_REPOSITORY:-}"
policy_allows_bump() { # owner/repo old-sha new-sha
    local action_repo="$1" old_sha="$2" new_sha="$3"
    local owner scope allowed patterns

    # GitHub-owned actions are controlled by github_owned_allowed rather than
    # patterns_allowed.  The two owners used here are the GitHub-owned action
    # namespaces present in this repository.
    case "$action_repo" in
        actions/* | github/*) return 0 ;;
    esac

    if [ -z "$POLICY_REPO" ]; then
        POLICY_REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
    fi
    if ! printf '%s' "$POLICY_REPO" | grep -qE '^[^/]+/[^/]+$'; then
        NOTES+=("FAILED $action_repo: could not resolve repository for selected-actions policy")
        FAILED=1
        return 1
    fi

    owner="${POLICY_REPO%%/*}"
    for scope in "repos/$POLICY_REPO" "orgs/$owner"; do
        if ! allowed="$(gh api "$scope/actions/permissions" -q .allowed_actions 2>/dev/null)" ||
            [ -z "$allowed" ]; then
            NOTES+=("FAILED $action_repo: could not read $scope Actions policy")
            FAILED=1
            return 1
        fi
        [ "$allowed" = selected ] || continue

        if ! patterns="$(gh api "$scope/actions/permissions/selected-actions" \
            -q '.patterns_allowed[]' 2>/dev/null)"; then
            NOTES+=("FAILED $action_repo: could not read $scope selected-actions patterns")
            FAILED=1
            return 1
        fi
        # If the current SHA is named exactly, it is a real external gate on
        # this update.  The candidate must be named exactly as well.  Retain
        # all existing entries: this script observes policy; it never widens
        # or mutates organization security settings.
        if printf '%s\n' "$patterns" | grep -Fqx "$action_repo@$old_sha" &&
            ! printf '%s\n' "$patterns" | grep -Fqx "$action_repo@$new_sha"; then
            NOTES+=("hold $action_repo: $new_sha is not admitted by $scope selected-actions policy")
            return 1
        fi
    done
    return 0
}

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

    key="${repo}@${major}"

    if [ -z "${RESOLVED_SHA[$key]:-}" ]; then
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
            RESOLVED_SHA[$key]="-"
            RESOLVED_TAG[$key]="-"
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
            RESOLVED_SHA[$key]="-"
            RESOLVED_TAG[$key]="-"
            continue
        fi

        RESOLVED_SHA[$key]="$new_sha"
        RESOLVED_TAG[$key]="$newest_in_major"

        if [ -n "$newest_any" ] &&
            ! printf '%s' "$newest_any" | grep -qE "^v?${major}(\.|$)"; then
            NOTES+=("$repo: newer MAJOR available ($newest_any) -- bump by hand, it may break")
        fi
    fi

    new_sha="${RESOLVED_SHA[$key]}"
    new_tag="${RESOLVED_TAG[$key]}"
    [ "$new_sha" = "-" ] && continue
    [ "$new_sha" = "$sha" ] && continue
    policy_allows_bump "$repo" "$sha" "$new_sha" || continue

    echo "bump $path: ${sha:0:12} ($tag) -> ${new_sha:0:12} ($new_tag)"
    CHANGED=1
    [ "$DRY_RUN" = 1 ] && continue

    # Validate the inventory owner before touching any workflow. A missing or
    # stale entry must leave both sides at the old commit, not fail after the
    # workflow has already been rewritten.
    python3 - "$repo" "$sha" "$new_sha" <<'PY'
import json, sys
from pathlib import Path

repo, old, new = sys.argv[1:]
data = json.loads(Path("ci/dependency-inventory.json").read_text(encoding="utf-8"))
matches = [
    dependency
    for dependency in data["dependencies"]
    if dependency.get("upstream") == f"https://github.com/{repo}"
]
if len(matches) != 1:
    raise SystemExit(f"action inventory entry missing or ambiguous: {repo}")
dependency = matches[0]
current = dependency.get("resolved_commit")
query_commit = dependency.get("osv_query", {}).get("commit")
if current not in (old, new) or query_commit != current:
    raise SystemExit(f"action inventory pin disagrees before bump: {repo}")
PY

    # Rewrite sha AND comment as one unit. Anchored on the exact old sha so a
    # second action pinned to a different sha in the same file is untouched.
    # `--` before the paths: a filename could otherwise be read as an option.
    while IFS= read -r f; do
        perl -pi -e "s{\Q$path\E\@\Q$sha\E # \Q$tag\E}{$path\@$new_sha # $new_tag}g" "$f"
    done < <(grep -rlF "$path@$sha" .github/ -- 2>/dev/null || grep -rlF "$path@$sha" .github/)

    # The advisory inventory is the machine-readable owner of this action
    # commit too. Move both its identity and the exact OSV commit query in the
    # same transaction as the workflow pin; a split update would either query
    # the old code or leave every scanner job red after an automated bump.
    python3 - "$repo" "$sha" "$new_sha" <<'PY'
import json, sys
from pathlib import Path

repo, old, new = sys.argv[1:]
path = Path("ci/dependency-inventory.json")
data = json.loads(path.read_text(encoding="utf-8"))
matches = [
    dependency
    for dependency in data["dependencies"]
    if dependency.get("upstream") == f"https://github.com/{repo}"
]
dependency = matches[0]
current = dependency.get("resolved_commit")
query = dependency.get("osv_query", {})
if current == new and query.get("commit") == new:
    raise SystemExit(0)
dependency["version"] = new
dependency["resolved_commit"] = new
query["commit"] = new
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
done

# The header comments in several workflows repeat the pin as documentation
# ("actions/checkout@v5 -> <sha>"). Those are the same second-copy hazard as the
# trailing tag comment, so keep them in step.
if [ "$DRY_RUN" = 0 ] && [ "$CHANGED" = 1 ]; then
    for key in "${!RESOLVED_SHA[@]}"; do
        s="${RESOLVED_SHA[$key]}"
        t="${RESOLVED_TAG[$key]}"
        repo="${key%@*}"
        key_major="${key##*@}"
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
        #
        # Restricted to THIS key's major line: the existing comment's own major
        # must equal key_major, or a repo pinned on two major lines (v3 in one
        # workflow, v4 in another) would have its v3 documentation overwritten
        # by the v4 resolution just because both share a repo name.
        # Hoisted into a variable rather than piped straight into `while`: an
        # action can legitimately have NO documentation comment (actions/cache
        # is pinned but never spelled out in a header), so grep exits 1. As the
        # last statement of this loop body that status became the body's status
        # and `set -e` killed the script -- BEFORE the FATAL guard below could
        # report, so the weekly bump died with no error text at all. `|| :`
        # keeps a no-match benign; an empty result then simply skips the loop.
        comment_files=$(grep -rlE "# ${repo}(/[A-Za-z0-9._-]+)?@v?${key_major}(\.[0-9A-Za-z._-]+)? +-> +[0-9a-f]{40}" .github/ 2>/dev/null || :)
        if [ -n "$comment_files" ]; then
            while IFS= read -r f; do
                perl -pi -e "s{(# \Q$repo\E(?:/[A-Za-z0-9._-]+)?\@)v?\Q$key_major\E(\.[0-9A-Za-z._-]+)?( +-> +)[0-9a-f]{40}}{\${1}$t\${3}$s}g" "$f"
            done <<<"$comment_files"
        fi
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
