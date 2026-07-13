#!/usr/bin/env bash
#
# Build nginx (or angie) with the shield module for local testing and CI.
#
#   tools/ci-build.sh [flavor] [version] [mode]
#     flavor : nginx (default) | angie
#     version: source version, e.g. 1.31.1
#     mode   : debug (default, dynamic .so) | asan (static, sanitizers)
#
# The built tree lives under ./.build. On success the paths of interest are:
#   .build/<dir>/objs/nginx                         (server binary)
#   .build/<dir>/objs/ngx_http_shield_module.so     (debug mode only)

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
MODE="${3:-debug}"
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
if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${DIR}.tar.gz" -C "$ROOT"
fi

# Strict flags: the module is hostile-input parser code, so warnings are errors.
CC_OPT="-g -Wall -Wextra -Wshadow"
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

cd "$ROOT/$DIR"

./configure \
    --with-compat \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

if [ "$MODE" = "asan" ]; then
    make -j"$(nproc)"
else
    make -j"$(nproc)" modules
    make -j"$(nproc)"
fi

echo "built: $ROOT/$DIR/objs/nginx"
