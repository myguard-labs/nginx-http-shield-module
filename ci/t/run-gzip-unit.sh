#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
output=${GZIP_UNIT_OUTPUT:-"$root/ci/t/gzip-unit-build"}
mkdir -p "$output"
# Match the daemon's O0 gcov mappings when CI combines this header's profiles.
optimization=-O1
case " ${EXTRA_CFLAGS:-} " in
    *" --coverage "* | *" -coverage "*) optimization=-O0 ;;
esac
# Intentional flag splitting matches the other native harness runners.
# shellcheck disable=SC2086
"${CC:-cc}" -std=c99 -g "$optimization" -Wall -Wextra -Werror \
    ${EXTRA_CFLAGS:-} "$root/ci/t/gzip_unit.c" -lz -o "$output/gzip_unit"
"$output/gzip_unit"
