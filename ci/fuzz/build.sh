#!/bin/sh
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/fuzz/build.sh -- Build all libFuzzer targets for ngx_http_shield_module.
#
# Usage:
#   bash ci/fuzz/build.sh          # build all targets into ci/fuzz/
#   bash ci/fuzz/build.sh clean    # remove built fuzz binaries
#
# Requirements: clang with -fsanitize=fuzzer support.
# The nginx source tree must be present at .build/nginx-<VER>-<mode>/ (as
# populated by ci/tools/ci-build.sh or a prior module build) -- the scan
# target links nginx's real ngx_unescape_uri()/ngx_strlow() out of
# src/core/ngx_string.c, so the decoder under test is production code, not a
# stub. NGX_BUILD_MODE selects which per-mode tree to use (default: debug) --
# each mode lives in its own tree so a mode switch never reuses another
# mode's object files.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_DIR="$REPO_ROOT/ci/fuzz"

if [ "${1:-}" = "clean" ]; then
    rm -f "$BIN_DIR/fuzz_scan"
    echo "fuzz binaries removed"
    exit 0
fi

# --- Locate nginx source headers. ------------------------------------------
NGX_BUILD_MODE="${NGX_BUILD_MODE:-debug}"
if [ -z "${NGINX_VERSION:-}" ]; then
    for d in "$REPO_ROOT"/.build/nginx-*-"$NGX_BUILD_MODE"/; do
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

NGX_SRC="$REPO_ROOT/.build/nginx-$NGINX_VERSION-$NGX_BUILD_MODE"
if [ ! -d "$NGX_SRC/src/core" ]; then
    echo "ERROR: nginx source not found at $NGX_SRC" >&2
    echo "       Run: bash ci/tools/ci-build.sh nginx $NGINX_VERSION $NGX_BUILD_MODE" >&2
    exit 1
fi
if [ ! -d "$NGX_SRC/objs" ]; then
    echo "ERROR: nginx not configured ($NGX_SRC/objs missing); the objs/ dir" >&2
    echo "       holds ngx_auto_config.h. Run ci/tools/ci-build.sh first." >&2
    exit 1
fi

echo "Using nginx source: $NGX_SRC"
echo "Building into: $BIN_DIR"
mkdir -p "$BIN_DIR"

CC="${CC:-clang}"
SANITIZERS="-fsanitize=fuzzer,address,undefined"
COMMON_CFLAGS="-g -O1 $SANITIZERS -fno-omit-frame-pointer"

# nginx core include paths (same set the module compiles against).
NGX_INCS="-I$NGX_SRC/src/core -I$NGX_SRC/src/event -I$NGX_SRC/src/event/modules \
    -I$NGX_SRC/src/os/unix -I$NGX_SRC/objs \
    -I$NGX_SRC/src/http -I$NGX_SRC/src/http/modules -I$NGX_SRC/src/http/v2"

# --- Build fuzz_scan (normalize + substring scan core). --------------------
# Links the module's REAL decision TU (src/ngx_http_shield_scan.c), not a copy
# of it. That is what the decision seam bought: the scanner takes bytes and
# caller-supplied scratch rather than an ngx_http_request_t, so the production
# source compiles into a standalone binary unchanged. A divergence found here
# is a divergence in shipped code.
#
# Also links nginx's real ngx_string.c so ngx_unescape_uri()/ngx_strlow() are
# the production decoder, plus ngx_palloc.c/ngx_alloc.c because
# ngx_http_shield_ac_build() builds the automata from a real ngx_pool_t.
echo
echo "==> Building fuzz_scan ..."
# shellcheck disable=SC2086
"$CC" $COMMON_CFLAGS $NGX_INCS \
    -I "$REPO_ROOT/src" \
    -o "$BIN_DIR/fuzz_scan" \
    "$REPO_ROOT/ci/fuzz/fuzz_scan.c" \
    "$REPO_ROOT/src/ngx_http_shield_scan.c" \
    "$NGX_SRC/src/core/ngx_string.c" \
    "$NGX_SRC/src/core/ngx_palloc.c" \
    "$NGX_SRC/src/os/unix/ngx_alloc.c"
echo "    OK: $BIN_DIR/fuzz_scan"

echo
echo "Build complete. Binaries in $BIN_DIR/"
echo
echo "Quick smoke-run (15 s):"
echo "  $BIN_DIR/fuzz_scan -max_total_time=15 $REPO_ROOT/ci/fuzz/corpus/fuzz_scan"
