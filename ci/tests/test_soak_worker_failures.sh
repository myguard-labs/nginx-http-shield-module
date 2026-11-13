#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/nginx" <<'SCRIPT'
#!/usr/bin/env python3
import signal
import time

def stop(_signum, _frame):
    raise SystemExit(0)

signal.signal(signal.SIGQUIT, stop)
signal.signal(signal.SIGTERM, stop)
while True:
    time.sleep(0.05)
SCRIPT
cat >"$tmp/curl" <<'SCRIPT'
#!/usr/bin/env bash
state="${SOAK_FAKE_STATE:?}"
exec 9>>"$state/lock"
flock 9

# Readiness does not use -w. Wait until load traffic has established both the
# benign and blocked controls, then make the next worker request fail. The
# duration is only a safety bound; injection no longer depends on throughput.
case " $* " in
    *" -w "*) worker=1 ;;
    *) worker=0 ;;
esac
if [ "$worker" -eq 1 ] && [ -e "$state/pass" ] && [ -e "$state/block" ] \
    && [ ! -e "$state/failed" ]; then
    : >"$state/failed"
    exit 7
fi
case " $* " in
    *" -X POST "*) code=403 ;;
    *union*|*passwd*|*jndi*|*shell.php*|*.env*|*.git*) code=403 ;;
    *) code=200 ;;
esac
if [ "$worker" -eq 1 ]; then
    [ "$code" = 403 ] && : >"$state/block"
    [ "$code" = 200 ] && : >"$state/pass"
fi
printf '%s' "$code"
SCRIPT
chmod +x "$tmp/nginx" "$tmp/curl"
python3 -m py_compile "$tmp/nginx"
mkdir "$tmp/state"
export SOAK_CURL="$tmp/curl" SOAK_FAKE_STATE="$tmp/state"
rc=0
RANDOM=1 bash "$root/ci/tools/soak.sh" "$tmp/nginx" 5 1 >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || {
    cat "$tmp/out"
    echo "soak accepted a failed worker" >&2
    exit 1
}
grep -q 'load worker(s) saw a curl transport failure' "$tmp/out"
[ -e "$tmp/state/failed" ] || {
    cat "$tmp/out"
    echo "fake curl did not inject the transport failure" >&2
    exit 1
}
if grep -q 'no attack was blocked\|no benign request passed' "$tmp/out"; then
    cat "$tmp/out"
    echo "fake traffic did not establish both positive controls" >&2
    exit 1
fi
printf 'ok   soak propagates transport failure after both traffic controls\n'
