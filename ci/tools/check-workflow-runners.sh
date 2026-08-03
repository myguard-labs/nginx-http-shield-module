#!/usr/bin/env bash
# Enforce the runner trust boundary for this PUBLIC repository.
#
# A `pull_request`-triggered job checks out and executes repository scripts from
# the pull request head. On a self-hosted runner that hands an arbitrary fork
# author code execution on the build host, so every pull_request-triggered
# workflow must run on a GitHub-hosted runner. The self-hosted label is reserved
# for workflows whose triggers are all owner-controlled (push/schedule/dispatch).
#
# Fails with a non-zero status and a list of offending workflows.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

for wf in .github/workflows/*.yml; do
    # Does this workflow have a pull_request trigger?
    if ! python3 - "$wf" <<'PY'; then
import sys
import yaml

with open(sys.argv[1]) as fh:
    doc = yaml.safe_load(fh)

# YAML 1.1 parses a bare `on:` key as the boolean True.
triggers = doc.get("on", doc.get(True, {})) or {}
if isinstance(triggers, str):
    triggers = {triggers: None}
if isinstance(triggers, list):
    triggers = dict.fromkeys(triggers)

sys.exit(0 if "pull_request" in triggers or "pull_request_target" in triggers else 1)
PY
        continue
    fi

    if grep -qE '^\s*runs-on:.*self-hosted' "$wf"; then
        echo "ERROR: $wf is pull_request-triggered and uses a self-hosted runner." >&2
        echo "       Public-repo fork PRs would execute on the build host." >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "Move those jobs to a GitHub-hosted runner (runs-on: ubuntu-latest)." >&2
    exit 1
fi

echo "OK: no pull_request-triggered workflow uses a self-hosted runner."
