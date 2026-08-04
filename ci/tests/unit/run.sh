#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tests/unit/run.sh -- build and run the scan-core unit tests.
#
#   ci/tests/unit/run.sh            # build with warnings-as-errors, then run
#   ci/tests/unit/run.sh clean      # remove the built binary and objects
#   COVERAGE=1 ci/tests/unit/run.sh # also instrument, so ci/tools/coverage.sh
#                                   # can gcov src/ afterwards
#
# Env:
#   CC                 compiler (default cc). Takes a full driver line, so
#                      CC="gcc -m32" runs the suite as a 32-bit binary.
#   NGINX_VERSION      which .build/nginx-<ver>-<mode>/ tree to take headers
#                      and ngx_string.c/ngx_palloc.c/ngx_alloc.c from.
#                      Autodetected by globbing .build/nginx-*-$NGX_BUILD_MODE/
#                      the same way ci/t/run-ban-unit.sh and ci/fuzz/build.sh
#                      do, when unset.
#   NGX_BUILD_MODE     which per-mode build tree to use (default: debug). Each
#                      mode built by ci/tools/ci-build.sh lives in its own
#                      tree (.build/nginx-<ver>-<mode>/) so a mode switch never
#                      reuses another mode's object files.
#
# Exit: 0 all checks passed, 1 a check failed or the build failed.
#
# Runs in well under a second and needs no nginx process, no network and no
# root -- so it is the layer that can afford to run on every save, and the
# layer that stays usable under a cross toolchain.
#
# WHAT IT DOES *NOT* DO, deliberately: it does not shim nginx. The test binary
# links the REAL src/core/ngx_string.c, ngx_palloc.c and src/os/unix/ngx_alloc.c
# out of the build tree -- the same set ci/fuzz/build.sh links for fuzz_scan --
# which is why a configured tree must exist first (ci/tools/ci-build.sh). A
# shimmed ngx_unescape_uri()/ngx_strlow() would make this hermetic and
# worthless: the decoder is the single most likely place for our matching to
# diverge from what nginx actually serves, so a test asserting against a
# private copy of it asserts only that the copy is self-consistent. Paying a
# build dependency to keep the decoder honest is the right side of that trade.
#
# ngx_http_shield_ac_build() needs a real ngx_pool_t (ngx_pcalloc for the
# permanent tables, ngx_create_pool/ngx_destroy_pool for build scratch), so
# ngx_palloc.c and ngx_alloc.c are linked too -- there is no allocator stub
# here, unlike the skeleton module's ci/fuzz/ngx_stubs.c, because shield has
# neither an ngx_stubs.c nor a nginx-tree.sh helper to reuse.
#
# -Werror applies to OUR translation units only (test_scan.c and
# ngx_http_shield_scan.c). ngx_string.c/ngx_palloc.c/ngx_alloc.c are upstream
# code we neither own nor patch, and gating on warnings in them would make an
# nginx version bump look like a test regression.
#
# SEEN RED -- every mutation below was APPLIED to src/ngx_http_shield_scan.c
# and the named check(s) were observed failing, with the automaton rebuilt
# from the mutated source in the same run (2026-08-04). Re-run them after
# touching the scan core or this script: a check that has never failed is not
# known to be a check.
#
#   * matcher never fires -- `return NULL;` at the top of
#     ngx_http_shield_ac_scan(), right after the `ac->nstates == 0` guard
#       -> 39 of 48 checks FAIL: every positive-hit case in case_category_
#          hits, case_percent_decoding, case_case_folding, case_skip_mask
#          (skip==0), case_malformed_and_embedded_nul, case_raw_vs_
#          decoded_split and all 7 of case_category_tiebreak (a matcher that
#          never fires cannot reach a tiebreak). The 9 that stay green are
#          exactly the ones that
#          assert CLEAN/DECLINED (case_clean_baseline in full, the
#          double-encoding non-match, the skip_sqli-declined check, the two
#          malformed-tail checks, and the "no bare '/.' signature" negative
#          in case_raw_vs_decoded_split) -- proving those checks do not
#          depend on the matcher ever firing, which is exactly why
#          case_clean_baseline has to exist on its own: a matcher that never
#          fires passes every "this stays clean" case in the file.
#   * skip mask ignored -- change `ac->out[s] & ~skip` to `ac->out[s]` in
#     ngx_http_shield_ac_scan() (drop the `~skip` term)
#       -> "skipping CAT_SQLI makes the same sqli input clean" FAILS (1 of 3
#          in case_skip_mask). The other two in that case stay green
#          (skip==0 and skip_xss are both supposed to still match), which is
#          the asymmetry that proves the mask, not the matcher, is under test.
#   * decoded lowercasing removed -- delete the
#     `ngx_strlow(dec, dec, dlen);` call in ngx_http_shield_scan_input()
#     (leave the decoded copy mixed-case)
#       -> all 3 case_case_folding checks that assert on the DECODED buffer
#          FAIL ("uppercase sqli marker matches", "uppercase sqli hit still
#          reports CAT_SQLI", "mixed-case sqli marker matches"); the
#          RAW-folded overlong check in the same case stays green, because
#          ngx_strlow(raw_lc, data, len) is a separate call this mutation
#          does not touch -- the asymmetry is deliberate, see the note in
#          case_case_folding.
#   * raw lowercasing removed -- change `ngx_strlow(raw_lc, data, len);` to
#     `ngx_memcpy(raw_lc, data, len);` in ngx_http_shield_scan_input()
#       -> both "uppercase-hex overlong escape matches (raw copy folded
#          too)" and "folded overlong hit still reports CAT_OVERLONG" FAIL:
#          NGX_HTTP_SHIELD_SIG("%c0%af") is stored lowercase and the RAW
#          automaton never folds case itself, so an uppercase-hex input
#          copied verbatim no longer matches. Every DECODED-only check stays
#          green, confirming the two lowercasing calls are independent code
#          paths this file exercises separately.
#   * '+' -> space fold disabled -- change the
#     `if (dec[i] == '+') { dec[i] = ' '; }` loop's condition to
#     `dec[i] == '+' && 0` in ngx_http_shield_scan_input()
#       -> both "'+' folds to a literal space, completing the sqli
#          signature" and "'+'-folded sqli hit reports CAT_SQLI" FAIL: with
#          '+' left as a literal, "or+1=1--" never forms the sqli signature
#          "or 1=1--" (space-separated), so the request stays clean. The
#          category-identity check FAILing too (rather than vacuously
#          passing) depends on the poisoned-hit sentinel described in
#          scan_str_skip()'s comment: an earlier version of this harness
#          zeroed the hit struct before each scan, which happens to alias
#          NGX_HTTP_SHIELD_CAT_SQLI == 0 and made this exact check pass
#          silently under this exact mutation. Fixed by poisoning to
#          NGX_HTTP_SHIELD_CAT_N (one past the last real category, never a
#          genuine hit) instead of zero.
#
#   * category tiebreak inverted -- `if (row < best)` -> `if (row > best)` in
#     ngx_http_shield_ac_scan(), with `best` initialized to `0` instead of
#     NGX_HTTP_SHIELD_NCATEGORIES so the loop still converges: report the
#     HIGHEST accepting table row instead of the lowest when one automaton
#     state accepts more than one category
#       -> exactly 2 of case_category_tiebreak's 7 checks FAIL ("the
#          multi-category state resolves to the LOWEST table row" and "the
#          tiebreak winner's NAME is reported"): the shared state reports
#          java_eval (row 13) instead of deserial (row 9). The case's other
#          5 checks stay green on purpose -- the two fixture-liveness checks
#          assert the suffix alone still reports java_eval (true under both
#          implementations), and the two skip checks assert the runner-up is
#          reported once the winner is masked out, which the inversion also
#          preserves. That asymmetry is what proves the TIEBREAK is under
#          test rather than the matcher or the skip mask.
#
#          This mutation was UNREACHABLE from this file until 2026-08-04 and
#          was recorded here as a known gap: every other fixture reaches its
#          accepting state by a path unique to one category's own table row,
#          so inverting the tiebreak left all 41 checks green. Closing it
#          needed a fixture built from two signatures that share a common
#          suffix ACROSS categories (out[v] |= out[fail[v]] in
#          ngx_http_shield_ac_build()). There is no seam to inject synthetic
#          signatures -- the automata are built from the production tables --
#          so the fixture is a real shipped pair, deserial's
#          "<java.lang.processbuilder" over java_eval's
#          "java.lang.processbuilder". See case_category_tiebreak()'s comment
#          in test_scan.c, including what goes stale if either literal is
#          ever edited out of ngx_http_shield_patterns.h.
#
# Extend: add a CASE() to test_scan.c and one line to its main(). New source
# file in src/ -> add it to the compile list below.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
BIN="$DIR/test_scan"

if [ "${1:-}" = "clean" ]; then
    # *.o too: this script produces them below and .gitignore already lists
    # them as generated. Leaving them behind meant `clean` did not give you a
    # clean tree -- switching $CC (say to `gcc -m32` for a 32-bit run) then
    # relinked stale objects from the previous toolchain.
    rm -f "$BIN" "$DIR"/*.o "$DIR"/*.gcda "$DIR"/*.gcno
    echo "unit test binary removed"
    exit 0
fi

# --- Locate a configured nginx source tree, same lookup as
# ci/t/run-ban-unit.sh and ci/fuzz/build.sh (no ci/tools/nginx-tree.sh exists
# in this module -- do not invent one here). ------------------------------
NGX_BUILD_MODE="${NGX_BUILD_MODE:-debug}"
if [ -z "${NGINX_VERSION:-}" ]; then
    for d in "$ROOT"/.build/nginx-*-"$NGX_BUILD_MODE"/; do
        [ -d "$d" ] || continue
        v=${d%/}
        v=${v##*/nginx-}
        v=${v%"-$NGX_BUILD_MODE"}
        case "$v" in *.tar*) continue ;; esac
        NGINX_VERSION=$v # last glob match wins; single tree in practice
    done
fi
if [ -z "${NGINX_VERSION:-}" ]; then
    echo "ERROR: could not determine NGINX_VERSION; run ci/tools/ci-build.sh first" >&2
    exit 1
fi

NGX_SRC="$ROOT/.build/nginx-$NGINX_VERSION-$NGX_BUILD_MODE"
if [ ! -d "$NGX_SRC/objs" ]; then
    echo "ERROR: nginx not configured ($NGX_SRC/objs missing)." >&2
    echo "       Run: bash ci/tools/ci-build.sh nginx $NGINX_VERSION $NGX_BUILD_MODE" >&2
    exit 1
fi
echo "Using nginx source: $NGX_SRC"

CC="${CC:-cc}"

NGX_INCS=(
    -I"$NGX_SRC/src/core"
    -I"$NGX_SRC/src/event"
    -I"$NGX_SRC/src/event/modules"
    -I"$NGX_SRC/src/os/unix"
    -I"$NGX_SRC/objs"
    -I"$NGX_SRC/src/http"
    -I"$NGX_SRC/src/http/modules"
)

# Our code: the full warning wall. A 32-bit or otherwise non-amd64 run that
# only passes with these loosened is hiding the exact class of defect they
# exist for.
OWN_CFLAGS=(-g -O1 -Wall -Wextra -Wshadow -Wstrict-prototypes -Werror)
# Upstream code: warnings visible, not fatal (see the header).
NGX_CFLAGS=(-g -O1 -Wall)

if [ "${COVERAGE:-0}" = 1 ]; then
    OWN_CFLAGS+=(--coverage)
    NGX_CFLAGS+=(--coverage)
    LINK_EXTRA=(--coverage)
else
    LINK_EXTRA=()
fi

echo "==> Building $BIN with ${CC}"
# shellcheck disable=SC2086  # $CC may legitimately carry flags (e.g. "gcc -m32")
$CC "${OWN_CFLAGS[@]}" "${NGX_INCS[@]}" -I"$ROOT/src" -c "$DIR/test_scan.c" \
    -o "$DIR/test_scan.o"
# shellcheck disable=SC2086
$CC "${OWN_CFLAGS[@]}" "${NGX_INCS[@]}" -I"$ROOT/src" \
    -c "$ROOT/src/ngx_http_shield_scan.c" -o "$DIR/ngx_http_shield_scan.o"
# shellcheck disable=SC2086
$CC "${NGX_CFLAGS[@]}" "${NGX_INCS[@]}" -c "$NGX_SRC/src/core/ngx_string.c" \
    -o "$DIR/ngx_string.o"
# shellcheck disable=SC2086
$CC "${NGX_CFLAGS[@]}" "${NGX_INCS[@]}" -c "$NGX_SRC/src/core/ngx_palloc.c" \
    -o "$DIR/ngx_palloc.o"
# shellcheck disable=SC2086
$CC "${NGX_CFLAGS[@]}" "${NGX_INCS[@]}" -c "$NGX_SRC/src/os/unix/ngx_alloc.c" \
    -o "$DIR/ngx_alloc.o"
# shellcheck disable=SC2086
$CC "${LINK_EXTRA[@]}" -o "$BIN" \
    "$DIR/test_scan.o" "$DIR/ngx_http_shield_scan.o" \
    "$DIR/ngx_string.o" "$DIR/ngx_palloc.o" "$DIR/ngx_alloc.o"

echo "==> Running"
"$BIN"
