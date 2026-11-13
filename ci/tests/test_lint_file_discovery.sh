#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$ROOT/ci/linter/lib.sh"

FILES=()
lint_files_into FILES '^ci/linter/lib\.sh$' ci/linter/lib.sh README.md
test "${#FILES[@]}" -eq 1
test "${FILES[0]}" = ci/linter/lib.sh

# A failed git listing must remain exit 2 through the array helper.  The old
# process-substitution callers discarded this status and certified an empty or
# truncated prefix as clean.
if (
    git() { return 1; }
    export LINT_MODE=all
    lint_files_into FILES '.'
); then
    echo 'failed git listing was reported clean' >&2
    exit 1
fi

echo 'lint file discovery controls: ok'
