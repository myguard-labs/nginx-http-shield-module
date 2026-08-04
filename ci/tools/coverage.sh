#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/coverage.sh -- harvest, report and gate module line coverage.
#
#   ci/tools/coverage.sh
#
# Env:
#   NGINX_VERSION        : required. Selects .build/nginx-$NGINX_VERSION-coverage
#                           as the coverage build tree (same variable the rest
#                           of ci/tools/*.sh and the workflow use). The
#                           "-coverage" suffix is hardcoded here because this
#                           script only ever runs against a coverage-mode
#                           build -- ci/tools/ci-build.sh gives every mode its
#                           own tree so a mode switch never reuses another
#                           mode's object files.
#   COVERAGE_FAIL_UNDER   : optional. Minimum acceptable module line coverage
#                           percentage. Default 92 -- the historical floor
#                           this script's inline predecessor enforced; changing
#                           it is a design decision, not a config tweak.
#
# Run from the module root, AFTER the coverage build and AFTER every harness
# that populates .gcda counters has run: `prove ci/t/`, the prober
# (`ci/t/prober/run.sh`), `ci/t/run-ban-unit.sh`, and `ci/tests/unit/run.sh`
# with COVERAGE=1. This script does not run any of them itself.
#
# Harvests coverage for the module's translation unit only, across three
# --directory args: the module TU built into nginx
# (.build/nginx-$NGINX_VERSION/objs/addon/src), the ban harness's object under
# ci/t/, and the scan-core harness's object under ci/tests/unit/. Upstream
# nginx .gcda is captured too (core is instrumented under the coverage build)
# but discarded by the --extract filter below.
#
# The remaining uncovered lines after a full harness run are config-time
# NGX_CONF_ERROR arms and OOM/alloc-failure returns that cannot be driven
# without malloc fault injection; the dot-segment arms unreachable behind
# nginx's own URI normalization carry LCOV_EXCL markers instead.
#
# FAILS LOUDLY, on purpose, rather than reporting 0%: a cached,
# non-instrumented build tree (no .gcda anywhere) is a broken CI setup, not a
# 0%-covered module, and must not be allowed to read as a real coverage
# finding.
#
# --- Verification (2026-08-04) ---
# Measured on a full coverage build + harness run (ci/t/, prober, ban unit,
# scan-core unit, all with counters populated):
#   $ COVERAGE_FAIL_UNDER=92 ci/tools/coverage.sh
#   module line coverage: 96.8%
#   (script exits 0)
# Control (a): floor set just above the measured rate --
#   $ COVERAGE_FAIL_UNDER=97 ci/tools/coverage.sh
#   module line coverage: 96.8%
#   coverage 96.8% below floor 97%
#   (exit 1)
# Control (b): no .gcda present (scratch dir with an unbuilt/uninstrumented
# tree) --
#   $ NGINX_VERSION=1.27.4 ci/tools/coverage.sh   # run against a tree with
#                                                  # no .gcda anywhere
#   FATAL: no .gcda files found under .build/nginx-1.27.4-coverage/objs/addon/src,
#   ci/t, ci/tests/unit -- coverage build/harness did not run; refusing to
#   report a false 0%
#   (exit 1, no cov.info produced)

set -euo pipefail

: "${NGINX_VERSION:?coverage.sh: NGINX_VERSION must be set}"
COVERAGE_FAIL_UNDER="${COVERAGE_FAIL_UNDER:-92}"

build=".build/nginx-${NGINX_VERSION}-coverage"
dir_addon="$build/objs/addon/src"
dir_t="ci/t"
dir_unit="ci/tests/unit"

if ! command -v lcov >/dev/null 2>&1; then
    echo "FATAL: lcov not found on PATH -- install it before running coverage.sh" >&2
    exit 1
fi

gcda_count=$(find "$dir_addon" "$dir_t" "$dir_unit" -name '*.gcda' 2>/dev/null | wc -l)
if [ "$gcda_count" -eq 0 ]; then
    echo "FATAL: no .gcda files found under $dir_addon, $dir_t, $dir_unit --" \
        "coverage build/harness did not run; refusing to report a false 0%" >&2
    exit 1
fi

lcov --capture --directory "$dir_addon" --directory "$dir_t" \
    --directory "$dir_unit" \
    --output-file cov.info --rc geninfo_unexecuted_blocks=1
lcov --extract cov.info '*ngx_http_shield*' --output-file cov-mod.info
lcov --list cov-mod.info

# Fail the job if module line coverage falls below the floor. The remaining
# uncovered lines are config-time NGX_CONF_ERROR arms and OOM/alloc-failure
# returns that cannot be driven without malloc fault injection; the
# dot-segment arms unreachable behind nginx's own URI normalization carry
# LCOV_EXCL markers instead.
rate=$(lcov --summary cov-mod.info 2>&1 |
    sed -n 's/.*lines\.*: \([0-9.]*\)%.*/\1/p')
echo "module line coverage: ${rate}%"
awk -v r="$rate" -v floor="$COVERAGE_FAIL_UNDER" 'BEGIN { exit (r+0 >= floor+0) ? 0 : 1 }' ||
    {
        echo "coverage ${rate}% below floor ${COVERAGE_FAIL_UNDER}%"
        exit 1
    }
