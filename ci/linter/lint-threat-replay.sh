#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Cheap corpus integrity checks; real baseline comparison runs with scan units.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
FILES=$(lint_files '^ci/(backend/|causal/|replay/|tools/threat-replay\.py$|tests/test_threat_replay\.py$|linter/lint-threat-replay\.sh$)' "$@") || exit $?
[ -n "$FILES" ] || exit 0
need python3 "apt-get install python3"
cd "$(repo_root)" || die "cannot enter repo root"
python3 ci/tools/threat-replay.py --validate
python3 ci/tests/test_threat_replay.py
python3 ci/causal/check.py --validate
python3 ci/causal/test_check.py
python3 -m py_compile ci/backend/check.py ci/backend/recorders.py
python3 ci/backend/test_recorders.py
