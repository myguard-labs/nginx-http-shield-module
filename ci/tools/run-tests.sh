#!/bin/sh
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/run-tests.sh -- run the Test::Nginx suite against a built module,
# on a port that is free RIGHT NOW rather than on Test::Nginx's fixed default.
#
# Why this exists: Test::Nginx binds TEST_NGINX_PORT, default 1984, and nothing
# arbitrates it. Two runs on one box -- two agents, two checkouts, a stray
# nginx from a crashed earlier run -- both take 1984 and the second dies with
#
#     nginx: [emerg] bind() to 127.0.0.1:1984 failed (98: Address already in use)
#     ... still could not bind()
#
# which READS like a regression in the module and is not one. Picking a free
# port per invocation removes the collision class entirely.
#
# Usage:
#   bash ci/tools/run-tests.sh                  # nginx, default version
#   bash ci/tools/run-tests.sh angie 1.12.0     # pick flavor + version
#   bash ci/tools/run-tests.sh nginx 1.31.3 -v  # extra args go to prove
#   TEST_NGINX_PORT=9999 bash ci/tools/run-tests.sh # honoured, not overridden
#
# Needs a build: ci/tools/ci-build.sh <flavor> <version>

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FLAVOR="${1:-nginx}"
[ $# -gt 0 ] && shift
VERSION="${1:-}"
[ $# -gt 0 ] && shift

# --- Locate the build tree. -------------------------------------------------
if [ -z "$VERSION" ]; then
    for d in "$REPO_ROOT"/.build/"$FLAVOR"-*/; do
        [ -d "$d" ] || continue
        v=${d%/}
        v=${v##*/"$FLAVOR"-}
        case "$v" in *.tar*) continue ;; esac
        VERSION=$v # last glob match wins; single tree in practice
    done
fi
if [ -z "$VERSION" ]; then
    echo "ERROR: no .build/$FLAVOR-* tree; run ci/tools/ci-build.sh $FLAVOR <ver>" >&2
    exit 1
fi

BUILD="$REPO_ROOT/.build/$FLAVOR-$VERSION"

# angie ships objs/angie, nginx ships objs/nginx.
BIN="$BUILD/objs/nginx"
[ -x "$BIN" ] || BIN="$BUILD/objs/angie"
MODULE="$BUILD/objs/ngx_http_shield_module.so"

for f in "$BIN" "$MODULE"; do
    if [ ! -e "$f" ]; then
        echo "ERROR: missing $f -- run: bash ci/tools/ci-build.sh $FLAVOR $VERSION" >&2
        exit 1
    fi
done

# --- Pick a free port. ------------------------------------------------------
# Ask the kernel for an ephemeral port and read back what it assigned, rather
# than guessing a number and hoping. There is an unavoidable race between
# closing this socket and nginx binding it, so retry a few times instead of
# treating one collision as fatal. Python is already a test dependency (the
# reporter suite), so this adds nothing new.
pick_port() {
    python3 -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
'
}

# An explicitly-set TEST_NGINX_PORT wins: a caller pinning a port (to attach a
# debugger, or to match a fixture) must not have it silently replaced.
if [ -n "${TEST_NGINX_PORT:-}" ]; then
    PORT="$TEST_NGINX_PORT"
    ATTEMPTS=1
    echo "==> Using pinned TEST_NGINX_PORT=$PORT"
else
    ATTEMPTS=5
fi

export TEST_NGINX_BINARY="$BIN"
export TEST_NGINX_LOAD_MODULES="$MODULE"
export TEST_NGINX_TIMEOUT="${TEST_NGINX_TIMEOUT:-20}"

# Keep each run's servroot separate too, and actually derive one per invocation
# rather than defaulting to the shared ci/t/servroot: two concurrent runs sharing it
# would overwrite each other's generated nginx.conf and pid file, which is the
# same collision class the port work removes. It also keeps the retry decision
# honest -- the bind-error grep below reads THIS run's error.log, so run A can no
# longer burn a retry on run B's failure. Still overridable.
export TEST_NGINX_SERVROOT="${TEST_NGINX_SERVROOT:-$REPO_ROOT/ci/t/servroot-$$}"

# A derived servroot is ours to clean up; an operator-supplied one is not.
if [ -z "${TEST_NGINX_SERVROOT_KEEP:-}" ] &&
    [ "$TEST_NGINX_SERVROOT" = "$REPO_ROOT/ci/t/servroot-$$" ]; then
    trap 'rm -rf "$TEST_NGINX_SERVROOT"' EXIT INT TERM
fi

i=1
while [ "$i" -le "$ATTEMPTS" ]; do
    [ -n "${TEST_NGINX_PORT:-}" ] || PORT="$(pick_port)"
    export TEST_NGINX_PORT="$PORT"

    echo "==> $FLAVOR $VERSION on 127.0.0.1:$TEST_NGINX_PORT (attempt $i/$ATTEMPTS)"

    set +e
    prove "$@" "$REPO_ROOT/ci/t/"
    rc=$?
    set -e

    # Only a bind collision is worth retrying on a different port; a genuine
    # test failure must surface immediately, not be re-run until it looks flaky.
    if [ "$rc" -ne 0 ] && [ "$ATTEMPTS" -gt 1 ] &&
        grep -qs "could not bind\|Address already in use" \
            "$TEST_NGINX_SERVROOT/logs/error.log"; then
        echo "==> port $PORT was taken; retrying on a fresh one" >&2
        i=$((i + 1))
        unset TEST_NGINX_PORT
        continue
    fi

    exit "$rc"
done

echo "ERROR: could not find a free port after $ATTEMPTS attempts" >&2
exit 1
