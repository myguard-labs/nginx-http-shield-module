#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-fuzz-dict.sh -- ci/fuzz/fuzz.dict is derived from the
# signature tables, not maintained by hand.
#
# The rule and the reasoning live in ci/tools/gen-fuzz-dict.py; this wrapper
# exists so run-all.sh picks the check up by glob and LINT_ONLY=fuzz-dict
# selects it.
#
# The failure it prevents is silent by construction. A libFuzzer dictionary is
# an optimization: an out-of-date one produces no error, no warning and a green
# fuzzing job -- it just means the mutator has to synthesize the new signature
# byte by byte, which within a 60s budget it will not do.
#
# Note what that does and does not cost, because the obvious metric does not
# show it. Edge coverage is UNCHANGED by the dictionary (measured: cov 199 both
# ways) -- the scan engine is an Aho-Corasick trie walk, so the same edges run
# whichever literal arrives. What a stale dict costs is SIGNATURE REACH: fewer
# distinct table literals actually driven through the differential oracle in
# fuzz_scan, and that oracle is the only thing that can catch the shipped
# engine disagreeing with the naive reference about WHICH signature matched.
# See the measurement table in ci/tools/gen-fuzz-dict.py.
#
# Same shape as the ASan-soak blindness found in cp10b: a working harness
# watching less than it appears to, with a green job either way.
#
# Usage: ci/linter/lint-fuzz-dict.sh [files...]   Env: LINT_MODE=staged|all
# Extend: a token that is not a table signature belongs in EXTRA_TOKENS in
# ci/tools/gen-fuzz-dict.py with a comment saying why, never appended to the
# generated file.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# Either side of the derivation can go stale: the header changing is the usual
# case, the dict being hand-edited is the other one. Trigger on both.
mapfile -t FILES < <(
    lint_files '^(src/ngx_http_shield_patterns\.h|ci/fuzz/fuzz\.dict)$' "$@"
)
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-fuzz-dict: signature table and dictionary both unchanged"
    exit 0
}

echo "lint-fuzz-dict: checking ci/fuzz/fuzz.dict against the signature tables"
need python3 "apt-get install python3"

# Whole-tree by nature: the dictionary is derived from the ENTIRE table, so the
# check reads both files in full regardless of which one was staged.
cd "$(repo_root)" || die "cannot enter the repo root"
exec ci/tools/gen-fuzz-dict.py --check
