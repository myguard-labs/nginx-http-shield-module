#!/usr/bin/env bash
# Prove the repository hook preserves both gate families while avoiding only
# the three C scanners already completed by ci/linter/run-all.sh.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/shield-hook-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
REAL_PRE_COMMIT="$(command -v pre-commit)"

# pre-commit itself, not the fixer process, compares the worktree before and
# after each hook. Prove a fixer that rewrites a file and exits zero still
# makes the framework return nonzero; the concurrent wrapper relies on this.
mkdir -p "$TMP/fixer-repo"
git -C "$TMP/fixer-repo" init -q
cat >"$TMP/fixer-repo/fix.sh" <<'SH'
#!/usr/bin/env bash
printf 'fixed\n' >"$1"
SH
chmod +x "$TMP/fixer-repo/fix.sh"
cat >"$TMP/fixer-repo/.pre-commit-config.yaml" <<'YAML'
repos:
  - repo: local
    hooks:
      - id: zero-exit-fixer
        name: zero-exit-fixer
        entry: ./fix.sh
        language: system
        files: ^probe$
YAML
printf 'dirty\n' >"$TMP/fixer-repo/probe"
git -C "$TMP/fixer-repo" add .pre-commit-config.yaml fix.sh probe
if (cd "$TMP/fixer-repo" && "$REAL_PRE_COMMIT" run zero-exit-fixer --files probe) \
    >"$TMP/fixer.out" 2>&1; then
    echo 'pre-commit accepted a zero-exit fixer mutation' >&2
    exit 1
fi
grep -q 'files were modified by this hook' "$TMP/fixer.out"
grep -qx 'fixed' "$TMP/fixer-repo/probe"

mkdir -p "$TMP/repo/.githooks" "$TMP/repo/ci/linter" "$TMP/bin"
cp "$ROOT/.githooks/pre-commit" "$TMP/repo/.githooks/pre-commit"
touch "$TMP/repo/.pre-commit-config.yaml"
git -C "$TMP/repo" init -q

cat >"$TMP/repo/ci/linter/run-all.sh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' lint-start >>"$TRACE/sequence"
printf '%s\n' "$*" >"$TRACE/run-all.args"
printf '%s\n' lint-end >>"$TRACE/sequence"
exit "${RUN_ALL_RC:-0}"
SH
cat >"$TMP/bin/pre-commit" <<'SH'
#!/usr/bin/env bash
printf '%s\n' pre-start >>"$TRACE/sequence"
printf '%s\n' "${SKIP-}" >"$TRACE/pre-commit.skip"
printf '%s\n' "$*" >"$TRACE/pre-commit.args"
printf '%s\n' pre-end >>"$TRACE/sequence"
exit "${PRE_COMMIT_RC:-0}"
SH
chmod +x "$TMP/repo/ci/linter/run-all.sh" "$TMP/bin/pre-commit"

export PATH="$TMP/bin:$PATH" TRACE="$TMP/trace"
mkdir -p "$TRACE"

(cd "$TMP/repo" && .githooks/pre-commit)
grep -Fx -- '--staged' "$TRACE/run-all.args"
grep -Fx -- 'flawfinder,cppcheck,semgrep' "$TRACE/pre-commit.skip"
grep -Fx -- 'run --hook-stage pre-commit' "$TRACE/pre-commit.args"

# A caller-supplied skip remains additive; it cannot re-enable duplicates.
(cd "$TMP/repo" && SKIP=check-yaml .githooks/pre-commit)
grep -Fx -- 'flawfinder,cppcheck,semgrep,check-yaml' "$TRACE/pre-commit.skip"

# Both gate failures are still propagated.  They run concurrently, so a red
# first gate no longer prevents the second from collecting its own evidence.
rm -f "$TRACE/pre-commit.args"
if (cd "$TMP/repo" && RUN_ALL_RC=1 .githooks/pre-commit); then
    echo 'run-all failure was not propagated' >&2
    exit 1
fi
test -e "$TRACE/pre-commit.args"
if (cd "$TMP/repo" && PRE_COMMIT_RC=1 .githooks/pre-commit); then
    echo 'pre-commit failure was not propagated' >&2
    exit 1
fi

# Exit 2 also covers discovery and configuration failures, so the wrapper
# must not misdiagnose every such failure as a missing linter installation.
if (cd "$TMP/repo" && RUN_ALL_RC=2 .githooks/pre-commit) \
    >"$TMP/lint-unavailable.out" 2>&1; then
    echo 'run-all unavailable failure was not propagated' >&2
    exit 1
fi
grep -Fq 'lint could not run (exit 2)' "$TMP/lint-unavailable.out"
grep -Fq 'discovery, configuration, or missing-tool error' \
    "$TMP/lint-unavailable.out"

# A partially staged worktree forces the race-free sequential path.
git -C "$TMP/repo" config user.name test
git -C "$TMP/repo" config user.email test@example.invalid
printf 'base\n' >"$TMP/repo/tracked"
git -C "$TMP/repo" add tracked .pre-commit-config.yaml
git -C "$TMP/repo" commit -qm baseline
printf 'unstaged\n' >>"$TMP/repo/tracked"
: >"$TRACE/sequence"
(cd "$TMP/repo" && .githooks/pre-commit)
printf '%s\n' lint-start lint-end pre-start pre-end >"$TMP/want-sequence"
diff -u "$TMP/want-sequence" "$TRACE/sequence"

echo 'pre-commit hook controls: ok'
