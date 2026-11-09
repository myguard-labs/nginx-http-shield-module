#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

flawfinder --minlevel=1 "$GITHUB_WORKSPACE/src/" 2>&1 | tee flawfinder.log
# Capture the scanner status separately: an if-pipeline would treat a scanner
# error like grep finding no high-severity hits.
report=$(flawfinder --minlevel=4 --quiet "$GITHUB_WORKSPACE/src/" 2>/dev/null)
if grep -Eq 'Hits = [1-9]' <<<"$report"; then
    echo "flawfinder: high-severity (>=4) findings present" >&2
    exit 1
fi
echo "flawfinder: clean at >=4"
