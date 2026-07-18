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

# nginx never frees its configuration pool, so LeakSanitizer reports the whole
# config parse as leaked on `nginx -t` and on every clean shutdown -- against an
# ASan build that turns the config test into a "Bail out!" before a single case
# runs. build-test.yml's ASan job disables leak detection for the same reason.
# Everything else ASan catches (use-after-free, overflow) stays on, which is the
# part worth having while the fault injector drives allocation-failure paths.
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

# The prober and json_test binaries are gitignored build products and run.sh
# does NOT build them. An edit to prober.c that was never compiled would
# otherwise be "verified" by the binary from before the edit: a green run that
# proves nothing about the change in hand. Same failure mode as a dead harness.
for ARTIFACT in ./prober ./json_test; do
    if [ -x "$ARTIFACT" ]; then
        STALE="$(find ./*.c ./*.h -newer "$ARTIFACT" 2>/dev/null || true)"

        if [ -n "$STALE" ]; then
            echo "Bail out! $ARTIFACT is older than its sources --" \
                 "run t/prober/build.sh:"
            printf '%s\n' "$STALE" | sed 's/^/# /'
            exit 1
        fi
    fi
done

# Check the oracle before trusting anything it says. Every rule assertion is
# evaluated against the JSON reader, so if that is broken the rules can all pass
# while proving nothing. Emitted as a bail-out rather than as extra TAP lines,
# so the plan the prober prints stays the plan the run reports.
if [ -x ./json_test ]; then
    if ! JSON_TEST_OUT="$(./json_test 2>&1)"; then
        echo "Bail out! prober JSON self-test failed:"
        printf '%s\n' "$JSON_TEST_OUT" | sed 's/^/# /'
        exit 1
    fi
else
    echo "Bail out! no json_test binary -- run t/prober/build.sh first"
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

# Stop the server synchronously rather than leaving it to the EXIT trap. kill(1)
# only delivers TERM; without waiting for the process to actually go, the script
# can return while workers are still writing out their .gcda files, and the
# coverage job downstream then reads a partial profile. Waiting also means the
# error-log grep below reads a file nobody is still appending to.
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# Surface worker crashes: a segfault shows up as [alert] in the error log even
# when every individual assertion passed.
if grep -qE '\[(alert|emerg)\]' "$PREFIX/logs/error.log" 2>/dev/null; then
    echo "# server logged an alert/emerg:"
    grep -E '\[(alert|emerg)\]' "$PREFIX/logs/error.log" | sed 's/^/# /'
    STATUS=1
fi

exit $STATUS
