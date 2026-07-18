#!/bin/sh
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# t/run-ban-unit.sh -- build and run the shield_ban direct-call unit harness.
#
# Compiles t/ban_unit.c against the real src/ngx_http_shield_ban.c plus nginx's
# own ngx_rbtree.c, with a malloc-backed fake slab pool (defined in the harness).
# No network, no nginx runtime; a synthetic clock is passed per call so the
# window / eviction / ban-expiry paths Test::Nginx cannot reach are exercised.
#
# Needs a configured nginx tree under .build/ (run tools/ci-build.sh first) for
# the core headers and ngx_rbtree.c. Honours CC / EXTRA_CFLAGS (the CI coverage
# job passes --coverage so ban.c's gcda merges into the module floor).
#
# Usage:
#   bash t/run-ban-unit.sh              # build + run
#   CC=clang EXTRA_CFLAGS="-fsanitize=address,undefined" bash t/run-ban-unit.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Locate a configured nginx source tree. --------------------------------
if [ -z "${NGINX_VERSION:-}" ]; then
    for d in "$REPO_ROOT"/.build/nginx-*/; do
        [ -d "$d" ] || continue
        v=${d%/}; v=${v##*/nginx-}
        case "$v" in *.tar*) continue;; esac
        NGINX_VERSION=$v   # last glob match wins; single tree in practice
    done
fi
if [ -z "${NGINX_VERSION:-}" ]; then
    echo "ERROR: could not determine NGINX_VERSION; run tools/ci-build.sh first" >&2
    exit 1
fi

NGX_SRC="$REPO_ROOT/.build/nginx-$NGINX_VERSION"
if [ ! -d "$NGX_SRC/objs" ]; then
    echo "ERROR: nginx not configured ($NGX_SRC/objs missing)." >&2
    echo "       Run: bash tools/ci-build.sh nginx $NGINX_VERSION" >&2
    exit 1
fi

CC="${CC:-cc}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"

NGX_INCS="-I$NGX_SRC/src/core -I$NGX_SRC/src/event -I$NGX_SRC/src/event/modules \
    -I$NGX_SRC/src/os/unix -I$NGX_SRC/objs"

BIN="$SCRIPT_DIR/ban_unit"

echo "==> Building ban_unit (nginx $NGINX_VERSION, CC=$CC) ..."
# shellcheck disable=SC2086
"$CC" -g -O0 -Wall -Wextra $EXTRA_CFLAGS $NGX_INCS \
    -o "$BIN" \
    "$SCRIPT_DIR/ban_unit.c" \
    "$REPO_ROOT/src/ngx_http_shield_ban.c" \
    "$NGX_SRC/src/core/ngx_rbtree.c"

echo "==> Running ban_unit ..."
"$BIN"
