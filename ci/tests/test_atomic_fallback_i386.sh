#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Prove that the atomic capability fixture really selects nginx's fallback
# backend when the compiler itself targets i386.  A configured nginx tree is
# required for the production headers; no nginx process is started.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${NGX_BUILD_MODE:-debug}"
version="${NGINX_VERSION:-}"

if [[ -z "$version" ]]; then
    for tree in "$root"/.build/nginx-*-"$mode"/; do
        [[ -d "$tree" ]] || continue
        candidate="${tree%/}"
        candidate="${candidate##*/nginx-}"
        candidate="${candidate%-"$mode"}"
        [[ "$candidate" == *.tar* ]] || version="$candidate"
    done
fi

if [[ -z "$version" ]]; then
    echo "ERROR: configured nginx tree not found; run ci/tools/ci-build.sh first" >&2
    exit 1
fi

nginx="$root/.build/nginx-$version-$mode"
binary="$(mktemp /tmp/shield-atomic-i386.XXXXXX)"
trap 'rm -f "$binary"' EXIT

gcc -m32 -g -O2 -Wall -Wextra -Wno-unused-parameter \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -DNGX_HAVE_GCC_ATOMIC=0 -DNGX_HAVE_LIBATOMIC=0 \
    -DNGX_DARWIN_ATOMIC=0 \
    -U__amd64__ -U__amd64 -U__i386__ -U__i386 -U_M_IX86 \
    -I"$nginx/src/core" -I"$nginx/src/event" \
    -I"$nginx/src/event/modules" -I"$nginx/src/os/unix" \
    -I"$nginx/objs" -I"$nginx/src/http" -I"$nginx/src/http/modules" \
    -DEXPECT_ATOMICS=0 \
    -o "$binary" "$root/ci/t/atomic_config_unit.c"

file "$binary" | grep -Eq 'ELF 32-bit.*Intel (80386|i386)'
"$binary"
