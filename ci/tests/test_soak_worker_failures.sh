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
counter="${SOAK_FAKE_COUNTER:?}"
exec 9>>"$counter.lock"
flock 9
count=0
[ ! -s "$counter" ] || read -r count <"$counter"
count=$((count + 1))
printf '%s\n' "$count" >"$counter"
if [ "$count" -gt 80 ]; then
    exit 7
fi
case " $* " in
    *" /ok "*) printf '200' ;;
    *" -X POST "*) printf '403' ;;
    *union*|*passwd*|*jndi*|*shell.php*|*.env*|*.git*) printf '403' ;;
    *) printf '200' ;;
esac
SCRIPT
chmod +x "$tmp/nginx" "$tmp/curl"
python3 -m py_compile "$tmp/nginx"
export SOAK_CURL="$tmp/curl" SOAK_FAKE_COUNTER="$tmp/count"
rc=0
RANDOM=1 bash "$root/ci/tools/soak.sh" "$tmp/nginx" 2 1 >"$tmp/out" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || {
    cat "$tmp/out"
    echo "soak accepted a failed worker" >&2
    exit 1
}
grep -q 'load worker(s) saw a curl transport failure' "$tmp/out"
if grep -q 'no attack was blocked\|no benign request passed' "$tmp/out"; then
    cat "$tmp/out"
    echo "fake traffic did not establish both positive controls" >&2
    exit 1
fi
printf 'ok   soak propagates transport failure after both traffic controls\n'
