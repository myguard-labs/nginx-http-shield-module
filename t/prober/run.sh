#!/usr/bin/env bash
#
# Boot a server with the probe-enabled module, run the prober rules against it,
# tear it down. Emits TAP on stdout, so `prove` consumes it like any other test.
#
#   t/prober/run.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what tools/ci-build.sh fetched
#
# The build must have been made with TEST_HARNESS=1, otherwise shield_probe
# does not exist and the config fails to load. run.sh checks for that up front
# rather than letting it surface as a confusing connect error.
set -euo pipefail

cd "$(dirname "$0")"

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.3}"
PORT="${PROBER_PORT:-18099}"

ROOT="$(cd ../.. && pwd)"
BUILD="$ROOT/.build/${FLAVOR}-${VERSION}"

# angie names its server binary objs/angie, nginx names it objs/nginx.
BIN="$BUILD/objs/nginx"
[ "$FLAVOR" = "angie" ] && BIN="$BUILD/objs/angie"

MODULE="$BUILD/objs/ngx_http_shield_module.so"

if [ ! -x "$BIN" ]; then
    echo "Bail out! no server binary at $BIN --" \
         "run: TEST_HARNESS=1 tools/ci-build.sh $FLAVOR $VERSION debug"
    exit 1
fi

# debug/module modes build a dynamic .so and need load_module; asan and
# coverage modes use --add-module and link the module into the binary, where a
# load_module line fails with "module is already loaded".
#
# Decide by looking inside the BINARY, not by whether a .so exists: switching
# build modes leaves the previous mode's .so behind in objs/, so a file-exists
# test picks the stale artifact and emits load_module for a static build.
if grep -qa shield_probe "$BIN"; then
    LOAD=""                                   # statically linked (asan/coverage)
elif [ -f "$MODULE" ] && grep -qa shield_probe "$MODULE"; then
    LOAD="load_module $MODULE;"               # dynamic (debug/module)
else
    echo "Bail out! neither $BIN nor $MODULE carries shield_probe --" \
         "rebuild with TEST_HARNESS=1"
    exit 1
fi

PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober.XXXXXX")"
trap 'rm -rf "$PREFIX"' EXIT

mkdir -p "$PREFIX/logs" "$PREFIX/conf"
sed -e "s#@LOAD@#$LOAD#" -e "s#@PORT@#$PORT#" \
    conf/prober.conf > "$PREFIX/conf/nginx.conf"

if ! "$BIN" -t -p "$PREFIX" -c conf/nginx.conf >"$PREFIX/logs/conftest" 2>&1; then
    echo "Bail out! config test failed:"
    sed 's/^/# /' "$PREFIX/logs/conftest"
    exit 1
fi

"$BIN" -p "$PREFIX" -c conf/nginx.conf &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$PREFIX"' EXIT

# Wait for the listener rather than sleeping a fixed interval: a fixed sleep is
# either slow or flaky, and on a loaded CI box it is both.
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        break
    fi
    sleep 0.1
done

STATUS=0
./prober -H 127.0.0.1 -p "$PORT" rules/*.rule || STATUS=$?

# Surface worker crashes: a segfault shows up as [alert] in the error log even
# when every individual assertion passed.
if grep -qE '\[(alert|emerg)\]' "$PREFIX/logs/error.log" 2>/dev/null; then
    echo "# server logged an alert/emerg:"
    grep -E '\[(alert|emerg)\]' "$PREFIX/logs/error.log" | sed 's/^/# /'
    STATUS=1
fi

exit $STATUS
