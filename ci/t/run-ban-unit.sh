#!/bin/sh
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/t/run-ban-unit.sh -- build and run the shield_ban direct-call unit harness.
#
# Compiles ci/t/ban_unit.c against the real src/ngx_http_shield_ban.c plus nginx's
# own ngx_rbtree.c, with a malloc-backed fake slab pool (defined in the harness).
# No network, no nginx runtime; a synthetic clock is passed per call so the
# window / eviction / ban-expiry paths Test::Nginx cannot reach are exercised.
#
# Needs a configured nginx tree under .build/ (run ci/tools/ci-build.sh first) for
# the core headers and ngx_rbtree.c. Honours CC / EXTRA_CFLAGS (the CI coverage
# job passes --coverage so ban.c's gcda merges into the module floor).
#
# NGX_BUILD_MODE selects which per-mode build tree to use (default: debug).
# Each mode built by ci/tools/ci-build.sh lives in its own tree
# (.build/nginx-<ver>-<mode>/) so a mode switch never reuses another mode's
# object files.
#
# Usage:
#   bash ci/t/run-ban-unit.sh           # build + run
#   CC=clang EXTRA_CFLAGS="-fsanitize=address,undefined" bash ci/t/run-ban-unit.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Locate a configured nginx source tree. --------------------------------
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
if [ ! -d "$NGX_SRC/objs" ]; then
    echo "ERROR: nginx not configured ($NGX_SRC/objs missing)." >&2
    echo "       Run: bash ci/tools/ci-build.sh nginx $NGINX_VERSION $NGX_BUILD_MODE" >&2
    exit 1
fi

CC="${CC:-cc}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"

NGX_INCS="-I$NGX_SRC/src/core -I$NGX_SRC/src/event -I$NGX_SRC/src/event/modules \
    -I$NGX_SRC/src/os/unix -I$NGX_SRC/objs"

BIN="$SCRIPT_DIR/ban_unit"

echo "==> Building ban_unit (nginx $NGINX_VERSION, CC=$CC) ..."
# shellcheck disable=SC2086
"$CC" -g -O0 -Wall -Wextra -pthread $EXTRA_CFLAGS $NGX_INCS \
    -o "$BIN" \
    "$SCRIPT_DIR/ban_unit.c" \
    "$REPO_ROOT/src/ngx_http_shield_ban.c" \
    "$NGX_SRC/src/core/ngx_rbtree.c"

echo "==> Running ban_unit ..."
"$BIN"

# Exercise the status renderer with allocation faults and maximum counters.
# Keep gcov data beside ban_unit for the existing CI coverage collector.
STATUS_BIN="$SCRIPT_DIR/status_unit"
ATOMIC_BIN="$SCRIPT_DIR/atomic_width_unit"
CONFIG_BIN="$SCRIPT_DIR/atomic_config_unit"
BODY_BIN="$SCRIPT_DIR/body_unit"
NEGOTIATE_BIN="$SCRIPT_DIR/negotiate_unit"
trap 'rm -f "$STATUS_BIN" "$ATOMIC_BIN" "$CONFIG_BIN-0" "$CONFIG_BIN-1" "$BODY_BIN" "$NEGOTIATE_BIN"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# shellcheck disable=SC2086
"$CC" -g -O0 -Wall -Wextra -Wno-unused-parameter $EXTRA_CFLAGS $NGX_INCS \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -o "$STATUS_BIN" \
    "$SCRIPT_DIR/status_unit.c" "$NGX_SRC/src/core/ngx_string.c"
"$STATUS_BIN"
python3 "$REPO_ROOT/ci/tests/test_module_dependencies.py" "$NGX_SRC/objs/Makefile"
# Exercise the bounded status-only query and Accept parser.
# shellcheck disable=SC2086
"$CC" -g -O0 -Wall -Wextra -Wno-unused-parameter $EXTRA_CFLAGS $NGX_INCS \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -o "$NEGOTIATE_BIN" \
    "$SCRIPT_DIR/negotiate_unit.c" "$NGX_SRC/src/core/ngx_string.c"
"$NEGOTIATE_BIN"
# Exercise nginx's Windows macro and LONG32 returns on this host.
# shellcheck disable=SC2086
"$CC" -g -O0 -Wall -Wextra -Werror $EXTRA_CFLAGS $NGX_INCS \
    -DNGX_WINDOWS_ATOMIC_HEADER=\"$NGX_SRC/src/os/win32/ngx_atomic.h\" \
    -o "$ATOMIC_BIN" "$SCRIPT_DIR/atomic_width_unit.c"
"$ATOMIC_BIN"
# Include the real module's config callbacks, discarding unrelated sections.
# ASan global registration would retain those discarded nginx callbacks and
# require a whole nginx link. Disable only global redzones in this isolated
# callback harness; its executable code and stack keep sanitizer instrumentation.
case "$("$CC" --version)" in
    *clang*) CONFIG_GLOBAL_FLAGS="-mllvm -asan-globals=0" ;;
    *) CONFIG_GLOBAL_FLAGS="--param=asan-globals=0" ;;
esac
# GCC expands the driver's --coverage after explicit -fno-* flags. Remove
# only that shorthand; retain sanitizer/strict flags and override gcov below.
CONFIG_EXTRA_CFLAGS=""
for config_flag in $EXTRA_CFLAGS; do
    case "$config_flag" in
        --coverage | -coverage) ;;
        *) CONFIG_EXTRA_CFLAGS="$CONFIG_EXTRA_CFLAGS $config_flag" ;;
    esac
done
for capability in 1 0; do
    CONFIG_PROFILE="$CONFIG_BIN-$capability-atomic_config_unit"
    rm -f "$CONFIG_PROFILE.gcda" "$CONFIG_PROFILE.gcno"
    CONFIG_CAP_FLAGS=""
    if [ "$capability" = 0 ]; then
        # Select nginx's actual Unix fallback backend on this x64 test host.
        CONFIG_CAP_FLAGS="-DNGX_HAVE_GCC_ATOMIC=0 -DNGX_HAVE_LIBATOMIC=0
            -DNGX_DARWIN_ATOMIC=0 -U__amd64__ -U__amd64"
    fi
    # shellcheck disable=SC2086
    # This counterfactual whole-module TU uses O2 and a different atomic
    # backend. Its discarded functions produce gcov line mappings absent
    # from the O0 native daemon. Keep its behavior/sanitizer checks, but only
    # the daemon and existing direct-call units populate target coverage.
    "$CC" -g -O2 -Wall -Wextra -Wno-unused-parameter \
        -ffunction-sections -fdata-sections -Wl,--gc-sections \
        $CONFIG_EXTRA_CFLAGS -fno-profile-arcs -fno-test-coverage \
        $CONFIG_GLOBAL_FLAGS $CONFIG_CAP_FLAGS $NGX_INCS \
        -I"$NGX_SRC/src/http" -I"$NGX_SRC/src/http/modules" \
        -DEXPECT_ATOMICS="$capability" \
        -o "$CONFIG_BIN-$capability" "$SCRIPT_DIR/atomic_config_unit.c"
    "$CONFIG_BIN-$capability"
    if [ -e "$CONFIG_PROFILE.gcda" ] || [ -e "$CONFIG_PROFILE.gcno" ]; then
        echo "ERROR: config harness polluted native daemon coverage" >&2
        exit 1
    fi
done
# Use the real body inspection path with deterministic allocation failure.
# Match the daemon's O0 coverage mappings so lcov can merge the unit profile.
BODY_PROFILE="$BODY_BIN-body_unit.gcda"
case " $EXTRA_CFLAGS " in
    *" --coverage "* | *" -coverage "*) rm -f "$BODY_PROFILE" ;;
esac
# shellcheck disable=SC2086
"$CC" -g -O0 -Wall -Wextra -Wno-unused-parameter \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    $EXTRA_CFLAGS \
    $CONFIG_GLOBAL_FLAGS $NGX_INCS \
    -I"$NGX_SRC/src/http" -I"$NGX_SRC/src/http/modules" \
    -o "$BODY_BIN" "$SCRIPT_DIR/body_unit.c" "$NGX_SRC/src/core/ngx_string.c"
"$BODY_BIN"
case " $EXTRA_CFLAGS " in
    *" --coverage "* | *" -coverage "*)
        if [ ! -s "$BODY_PROFILE" ]; then
            echo "ERROR: body harness did not produce coverage data" >&2
            exit 1
        fi
        ;;
esac
python3 "$REPO_ROOT/ci/tests/test_status_runner.py"
