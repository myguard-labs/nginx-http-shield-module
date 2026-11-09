#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Check direct and reusable-workflow PR jobs against the hosted-runner boundary.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 ci/tools/check-workflow-runners.py
