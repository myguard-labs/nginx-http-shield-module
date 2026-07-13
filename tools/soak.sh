#!/usr/bin/env bash
#
# Sustained scan-path soak for ngx_http_shield_module.
#
# Fires a mixed storm of attack payloads (must be blocked) and benign requests
# (must pass) at a `shield block` location, in both URI and request-body form,
# so the module's normalize + substring-scan + body-buffering paths churn for
# minutes under a sanitizer or valgrind. The single-shot Test::Nginx suite
# proves correctness once per case; this proves the same code stays clean under
# sustained, concurrent, adversarial load with no leak / OOB / race.
#
# Assertion is meaningful: a clean run must have seen at least one attack
# BLOCKED (403) and at least one benign request PASS -- so a green result
# proves both branches ran, not merely that nothing crashed.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 600 8
#   USE_HELGRIND=1 tools/soak.sh <nginx-binary> 600 8
#
# Build with ASAN for the ASAN path; plain debug for the valgrind path:
#   CC=clang bash tools/ci-build.sh nginx 1.31.1 asan
#   bash tools/ci-build.sh nginx 1.31.1 debug

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-120}"
CONC="${3:-8}"
PORT=18253

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"
echo ok > "$WORK/html/ok"

# Dynamic (.so next to the binary) vs static (asan) build detection.
NGINX_OBJS="$(cd "$(dirname "$NGINX")" && pwd)"
MODULE_SO="$NGINX_OBJS/ngx_http_shield_module.so"
if [ -f "$MODULE_SO" ]; then
    LOAD_MODULE="load_module $MODULE_SO;"
else
    LOAD_MODULE=""
fi

# empty_gif is a real content handler that reaches PRECONTENT (where shield
# runs); `return` would finalize in REWRITE, before shield ever sees the
# request. A POST body to empty_gif is a 405, so for body cases 403 = blocked,
# 405 = passed-through.
cat > "$WORK/conf/nginx.conf" <<EOF
$LOAD_MODULE
daemon off;
master_process on;
worker_processes 2;
worker_shutdown_timeout 5s;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;

    server {
        listen 127.0.0.1:$PORT;

        location = /ok {
            root $WORK/html;
            try_files /ok =404;
        }

        location / {
            shield block;
            shield_body on;
            shield_max_body 64k;
            shield_status 403;
            empty_gif;
        }
    }
}
EOF

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
SUPP="$(cd "$(dirname "$0")" && pwd)/valgrind.supp"
if [ "${USE_HELGRIND:-0}" = "1" ]; then
    VG=(valgrind --tool=helgrind --error-exitcode=99
        --gen-suppressions=all
        --log-file="$WORK/logs/valgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
elif [ "${USE_VALGRIND:-0}" = "1" ]; then
    VG=(valgrind --error-exitcode=99 --leak-check=full
        --errors-for-leak-kinds=definite
        --gen-suppressions=all
        --log-file="$WORK/logs/valgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
fi

"${RUN[@]}" &
NGINX_PID=$!

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$PORT/ok" 2>/dev/null && break
    sleep 0.1
done

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)'; [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (memcheck)')"
END=$(( $(date +%s) + DURATION ))

saw_block="$WORK/logs/saw_block"
saw_pass="$WORK/logs/saw_pass"
saw_dead="$WORK/logs/saw_dead"

# URL-encoded attack payloads across many categories (spaces -> %20; the
# harness/curl would otherwise mangle the request line). Each is something the
# module MUST block in block mode.
ATTACKS=(
    "/?id=1%20union%20select%20user,pass%20from%20users"
    "/..%2f..%2f..%2fetc%2fpasswd"
    "/%c0%af%c0%afwinnt/system32"
    "/search?q=%3Cscript%3Edocument.cookie%3C/script%3E"
    "/%24%7Bjndi:ldap://x/a%7D"
    "/x%00.jpg"
    "/latest/meta-data/169.254.169.254"
    "/wls-wsat/coordinatorporttype"
    "/shell.php?cmd=id"
    "/.env"
    "/.git/config"
    "/%7B%7B7*7%7D%7D"
)
# Bodies (POST) that must be blocked; empty_gif returns 405 when passed.
# shellcheck disable=SC2016  # $where is a literal NoSQL operator, not a variable
BODY_ATTACKS=(
    "id=1' or 1=1--"
    '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    '{"$where":"1==1"}'
)
BENIGN=(
    "/ok"
    "/index.html"
    "/api/v1/users?page=2&sort=name"
    "/assets/app.min.js?v=1.4.2"
    "/search?q=nginx+performance+tuning"
)

# A curl that never reached nginx yields 000. That is not a pass and not a
# block -- it is a dead server, and silently folding it into either bucket is
# how a soak against a crashed nginx reports "clean". Record it instead, and
# fail the run if any occurred.
storm_worker() {
    while [ "$(date +%s)" -lt "$END" ]; do
        r=$((RANDOM % 10))
        if [ "$r" -lt 5 ]; then
            u="${ATTACKS[$((RANDOM % ${#ATTACKS[@]}))]}"
            code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
                "http://127.0.0.1:$PORT$u" 2>/dev/null || echo 000)
        elif [ "$r" -lt 7 ]; then
            b="${BODY_ATTACKS[$((RANDOM % ${#BODY_ATTACKS[@]}))]}"
            code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
                -X POST --data "$b" \
                "http://127.0.0.1:$PORT/post" 2>/dev/null || echo 000)
        else
            u="${BENIGN[$((RANDOM % ${#BENIGN[@]}))]}"
            code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
                "http://127.0.0.1:$PORT$u" 2>/dev/null || echo 000)
            # benign: anything that is NOT a 403 block proves pass-through
            # (200/404/405 are all "shield let it through").
            if [ "$code" != "403" ] && [ "$code" != "000" ]; then
                : > "$saw_pass" 2>/dev/null || true
            fi
        fi

        if [ "$code" = "000" ]; then
            printf 'x' >> "$saw_dead" 2>/dev/null || true
        elif [ "$r" -lt 7 ] && [ "$code" = "403" ]; then
            : > "$saw_block" 2>/dev/null || true
        fi
    done
}

pids=()
for _ in $(seq 1 "$CONC"); do storm_worker & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || true; done

kill -QUIT "$NGINX_PID" 2>/dev/null || true
for _ in $(seq 1 30); do
    kill -0 "$NGINX_PID" 2>/dev/null || break
    sleep 1
done
if kill -0 "$NGINX_PID" 2>/dev/null; then
    echo "WARN: nginx did not exit after SIGQUIT; force-killing"
    kill -KILL "$NGINX_PID" 2>/dev/null || true
fi
# `set -e` would abort on a non-zero `wait`, so the exit status has to be
# captured in the same command, not by a following `rc=$?` (which was dead code).
rc=0
wait "$NGINX_PID" 2>/dev/null || rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASAN/UBSAN report:"; cat "$WORK"/logs/asan*; problems=1
fi
if ls "$WORK"/logs/valgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* 2>/dev/null; then
        echo "FAIL: valgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' "$WORK"/logs/valgrind.*
        for _vglog in "$WORK"/logs/valgrind.*; do
            grep -qE 'ERROR SUMMARY: [1-9]' "$_vglog" || continue
            echo "---- $_vglog ----"
            cat "$_vglog"
        done
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null \
        | grep -vE 'shared memory zone .* was locked by|open socket #[0-9]+ left in connection|\[alert\][^:]*: aborting'; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi
if [ -f "$saw_dead" ]; then
    echo "FAIL: $(wc -c < "$saw_dead") request(s) got no HTTP response (curl 000)" \
         "-- nginx was unreachable, so this soak proves nothing"
    tail -40 "$WORK/logs/error.log" || true
    problems=1
fi
if [ ! -f "$saw_block" ]; then
    echo "FAIL: no attack was blocked (403) -- soak is not exercising the block path"
    grep -iE 'shield' "$WORK/logs/error.log" | tail -20 || true
    problems=1
fi
if [ ! -f "$saw_pass" ]; then
    echo "FAIL: no benign request passed -- soak may be blocking everything"
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "soak clean: ${DURATION}s @ ${CONC} concurrent -- attack-block + benign-pass exercised, no sanitizer/leak/crash"
