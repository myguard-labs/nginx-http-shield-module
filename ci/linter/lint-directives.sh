#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
cd "$root"
python3 ci/linter/check-directive-docs.py
