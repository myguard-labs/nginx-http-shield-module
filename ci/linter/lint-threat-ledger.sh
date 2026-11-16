#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Validate the inherited inventory and its regression controls.

. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
FILES=$(lint_files '^(src/ngx_http_shield_patterns\.h|src/ngx_http_shield_module\.c|README\.md|ci/threat-ledger.*\.json|ci/tools/(threat-ledger|gen-fuzz-dict)\.py|ci/tests/test_threat_ledger\.py|ci/linter/lint-threat-ledger\.sh)$' "$@") || exit $?
[ -n "$FILES" ] || exit 0
need python3 "apt-get install python3"
cd "$(repo_root)" || die "cannot enter repo root"
python3 ci/tools/threat-ledger.py || exit $?
python3 ci/tests/test_threat_ledger.py
