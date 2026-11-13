#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/fanalyzer.sh -- run gcc's interprocedural analyser over src/*.c,
# replaying each file's real compile command out of compile_commands.json.
#
#   ci/tools/fanalyzer.sh [build-dir]
#     build-dir : holds compile_commands.json (default $GITHUB_WORKSPACE, else .)
#
# Writes fanalyzer.log in the working directory and exits non-zero if any file
# produced a diagnostic or had no database entry.
#
# WHY A SECOND ANALYSER. -fanalyzer is gcc's own engine, not a wrapper around
# clang's. The two overlap only partly and each reports leaks and double-frees
# the other misses, so running both is coverage rather than duplication. This
# lens is not theoretical here: a leak reached a default branch in this
# superrepo past a clean local lint pass and was caught by -fanalyzer in CI.
#
# THE FLAG TRAP. -fsyntax-only silently DISABLES -fanalyzer. Pairing them gives
# a step that exits 0 having analysed nothing -- a green cell that proves only
# that the flags were wrong. That is why this compiles with -c to a scratch
# object instead. Do not "speed it up" by going back to -fsyntax-only.
#
# WHY REPLAY THE DATABASE. A hand-kept include list is a second copy of
# configure's output and drifts both ways: the one this repo used to carry for
# clang-tidy had lost src/event/quic and gained paths the real build never
# passes. A wrong -I is not a loud failure for an analyser -- it keeps going and
# analyses a DIFFERENT translation unit than the one that ships. Replaying the
# recorded argv means the flags follow ci-build.sh with nothing to maintain.
#
# Usage note: entries record paths relative to their own "directory" field, so
# each command is run from there rather than from the checkout root.
set -euo pipefail

BUILD_DIR="${1:-${GITHUB_WORKSPACE:-.}}"
DB="$BUILD_DIR/compile_commands.json"
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "${GITHUB_WORKSPACE:-.}")"

command -v gcc >/dev/null || {
    echo "fanalyzer: gcc missing from PATH" >&2
    exit 2
}
command -v python3 >/dev/null || {
    echo "fanalyzer: python3 missing from PATH" >&2
    exit 2
}
# A missing database is a broken caller, not a clean run: exit 2 so it cannot be
# mistaken for "analysed everything, found nothing".
[ -f "$DB" ] || {
    echo "fanalyzer: no compile_commands.json at $DB" >&2
    exit 2
}

: >fanalyzer.log
status=0
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

for src in "$ROOT"/src/*.c; do
    [ -e "$src" ] || continue
    echo "--- gcc -fanalyzer: $(basename "$src") ---" | tee -a fanalyzer.log

    # Materialise NUL-delimited fields so spaces, quotes and globs in a real
    # compile argument survive exactly; command substitution cannot carry NUL.
    entry_file="$tmpdir/entry"
    if ! DB="$DB" SRC="$src" python3 "$ROOT/ci/tools/fanalyzer_args.py" \
        >"$entry_file"; then
        echo "fanalyzer: failed to read compile_commands entry for $src" >&2
        status=1
        continue
    fi
    mapfile -d '' -t entry <"$entry_file"

    if [ "${#entry[@]}" -eq 0 ]; then
        echo "fanalyzer: no compile_commands entry for $src" >&2
        status=1
        continue
    fi
    dir="${entry[0]}"
    args=("${entry[@]:1}")

    # THE EXIT STATUS IS NOT THE ORACLE. Analyser findings are WARNINGS and gcc
    # exits 0 on warnings. Verified 2026-08-24 (gcc 14.2.0, Debian) on a
    # deliberate malloc leak: `-Wanalyzer-malloc-leak` printed in full and gcc
    # still exited 0. A `|| status=1` on the compile alone is therefore a gate
    # that can never fire -- it would report clean on every leak forever.
    #
    # There is no -Werror=analyzer-* wildcard to promote them with: gcc 14
    # exposes ~50 individual -Wanalyzer-<name> options and no group, and
    # `-Werror=analyzer-all` is rejected outright ("no option -Wanalyzer-all").
    # Bare -Werror does work, but the replayed argv carries the BUILD's warning
    # flags, so it would also redden this step on any pre-existing upstream
    # warning unrelated to the analyser.
    #
    # So the oracle is the diagnostic text: any "[-Wanalyzer-" in the output is
    # a finding. A non-zero gcc exit still counts too -- that is a hard compile
    # error, which is a broken replay and must not read as clean.
    out=""
    out="$( (cd "$dir" && gcc -fanalyzer -c "${args[@]}" \
        -o /tmp/fanalyzer.o) 2>&1)" || status=1
    printf '%s\n' "$out" | tee -a fanalyzer.log
    case "$out" in
        *'[-Wanalyzer-'*) status=1 ;;
    esac
done

exit "$status"
