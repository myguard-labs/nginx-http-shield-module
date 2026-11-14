#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Direct-call allowlist failures/guards against a configured nginx/Angie tree.
# Usage: EXTRA_CFLAGS=--coverage bash ci/t/run-allowlist-unit.sh <build-tree>
# ALLOWLIST_VALGRIND=1 enables all leak kinds with no suppressions.
# Profiles remain in ci/t for ci/tools/coverage.sh; only the executable is removed.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
ngx_src=${1:?configured nginx/Angie build tree required}
compiler_args=$(mktemp)
binary="$root/ci/t/allowlist_unit"
trap 'rm -f "$binary" "$compiler_args"' EXIT
# Match the configured-build harness: parse shell-style words without executing them.
python3 -c 'import os, shlex, sys
try:
    args = shlex.split(os.environ.get("CC", "cc"))
    if not args:
        raise ValueError("empty compiler command")
    sys.stdout.buffer.write(b"".join(os.fsencode(arg) + b"\0" for arg in args))
except ValueError as exc:
    sys.exit(str(exc))' >"$compiler_args"
mapfile -d '' -t cc <"$compiler_args"
case "$("${cc[@]}" --version)" in
    *clang*) globals=(-mllvm -asan-globals=0) ;;
    *) globals=(--param=asan-globals=0) ;;
esac
read -r -a extra <<<"${EXTRA_CFLAGS:-}"
# A source change invalidates this harness's old gcov checksums.
case " ${extra[*]} " in
    *" --coverage "* | *" -coverage "* | *" -fprofile-arcs "*)
        rm -f "$binary"-*.gcda
        ;;
esac
"${cc[@]}" -g -O0 -Wall -Wextra -Werror -Wno-unused-parameter \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    "${globals[@]}" "${extra[@]}" \
    -I"$ngx_src/src/core" -I"$ngx_src/src/event" \
    -I"$ngx_src/src/event/modules" -I"$ngx_src/src/os/unix" \
    -I"$ngx_src/objs" -I"$ngx_src/src/http" -I"$ngx_src/src/http/modules" \
    -o "$binary" "$root/ci/t/allowlist_unit.c" \
    "$ngx_src/src/core/ngx_array.c" "$ngx_src/src/core/ngx_palloc.c" \
    "$ngx_src/src/os/unix/ngx_alloc.c" "$ngx_src/src/core/ngx_string.c" \
    "$ngx_src/src/core/ngx_inet.c"
case "${ALLOWLIST_VALGRIND:-0}" in
    0) "$binary" ;;
    1)
        valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
            --errors-for-leak-kinds=all --error-exitcode=97 "$binary"
        ;;
    *)
        echo 'ALLOWLIST_VALGRIND must be 0 or 1' >&2
        exit 2
        ;;
esac
