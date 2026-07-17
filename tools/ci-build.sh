#!/usr/bin/env bash
#
# Build nginx (or angie) with the shield module for local testing and CI.
#
#   tools/ci-build.sh [flavor] [version] [mode]
#     flavor : nginx (default) | angie
#     version: source version, e.g. 1.31.3
#     mode   : debug (default, dynamic .so) | asan (static, sanitizers)
#              | module (dynamic .so only, nginx core NOT compiled)
#              | coverage (static, gcov-instrumented module TU)
#
# The built tree lives under ./.build. On success the paths of interest are:
#   .build/<dir>/objs/nginx                         (server binary)
#   .build/<dir>/objs/ngx_http_shield_module.so     (debug/module mode)
#
# "module" mode exists for CodeQL. For compiled languages CodeQL builds its
# database from whatever the traced build actually compiles -- the workflow's
# paths/paths-ignore filters do NOT apply to C/C++. Building the nginx core
# therefore pulled all of nginx into the database and raised alerts against
# upstream code we neither own nor patch. Compiling only the module keeps the
# database limited to our translation unit.

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.3}"
MODE="${3:-debug}"

case "$MODE" in
    debug|asan|module|coverage) ;;
    *)
        echo "unsupported mode: $MODE (want: debug|asan|module)" >&2
        exit 2
        ;;
esac
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        DIR="nginx-${VERSION}"
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        DIR="angie-${VERSION}"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

mkdir -p "$ROOT"
if [ ! -f "$ROOT/${DIR}.tar.gz" ]; then
    curl -fsSL "$URL" -o "$ROOT/${DIR}.tar.gz"
fi

# Verify BEFORE extraction, and verify the cached copy too: a poisoned Actions
# cache is exactly as dangerous as a poisoned mirror, and HTTPS stops neither.
# An unrecorded version is a hard failure, never a silent trust decision.
DIGESTS="$MODULE_DIR/tools/sources.sha256"
if ! grep -qE "[[:space:]]${DIR}\.tar\.gz\$" "$DIGESTS"; then
    echo "no recorded sha256 for ${DIR}.tar.gz in tools/sources.sha256." >&2
    echo "Verify the upstream PGP signature, then record its digest." >&2
    exit 3
fi
(
    cd "$ROOT"
    grep -E "[[:space:]]${DIR}\.tar\.gz\$" "$DIGESTS" | sha256sum -c -
)

if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${DIR}.tar.gz" -C "$ROOT"
fi

# --with-cc-opt applies to UPSTREAM CORE as well as to our module, so it must
# carry only flags that upstream compiles cleanly under. -Wshadow does not
# qualify: angie 1.12.0's own ngx_http_client_module.c shadows a parameter, and
# angie's configure adds -Werror, so a -Wshadow here fails the core build before
# our code is ever reached. (nginx core happens to be -Wshadow-clean; that is
# luck, not a contract.)
#
# The module is hostile-input parser code and still gets the strict treatment --
# but scoped to its own translation unit by the "Strict module compile" step in
# build-test.yml, which recompiles src/ with -Wshadow -Werror and friends. That
# is the right boundary: our warnings are our problem, upstream's are not.
CC_OPT="-g -Wall"
LD_OPT=""
ADD_MODULE="--add-dynamic-module=$MODULE_DIR"

if [ "$MODE" = "asan" ]; then
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
    SAN="$SAN -fno-omit-frame-pointer -g -O1"
    if "${CC:-cc}" --version 2>/dev/null | grep -qi clang; then
        # nginx core trips a few benign UBSan sub-checks; silence only those.
        SAN="$SAN -fno-sanitize=function,nonnull-attribute,pointer-overflow"
    fi
    CC_OPT="$SAN -Wall"
    LD_OPT="$SAN"
    # Static build so the sanitizer runtime is linked into the server binary.
    ADD_MODULE="--add-module=$MODULE_DIR"
fi

if [ "$MODE" = "coverage" ]; then
    # gcov instrumentation. --coverage == -fprofile-arcs -ftest-coverage; it is
    # applied core-wide (configure has no per-module cc-opt hook), but the CI job
    # harvests gcov only for our translation unit, so upstream .gcda is ignored.
    # Static link (--add-module) so the instrumented module runs inside the very
    # server binary the tests drive, and .gcda lands next to objs/.
    CC_OPT="-g -O0 --coverage -Wall"
    LD_OPT="--coverage"
    ADD_MODULE="--add-module=$MODULE_DIR"
fi

cd "$ROOT/$DIR"

./configure \
    --with-compat \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

case "$MODE" in
    asan|coverage)
        make -j"$(nproc)"
        echo "built: $ROOT/$DIR/objs/nginx"
        ;;
    module)
        # Only the module .so -- deliberately no full `make`, so the nginx core
        # is never compiled and never enters a traced CodeQL database.
        make -j"$(nproc)" modules
        echo "built: $ROOT/$DIR/objs/ngx_http_shield_module.so"
        ;;
    *)
        make -j"$(nproc)" modules
        make -j"$(nproc)"
        echo "built: $ROOT/$DIR/objs/nginx"
        ;;
esac
