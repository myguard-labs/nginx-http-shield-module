#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
need python3 "apt-get install python3"
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" coverage
