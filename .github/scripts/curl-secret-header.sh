#!/usr/bin/env bash
# sync-sha: d91a225a9535dd2ff2bae985ff765f90c720f6b877dc7bf1cb6c186aa60b1142
# Pass a secret-backed HTTP header to curl without exposing its value in argv.
set -euo pipefail

header="${1:?header name required}"
scheme="${2-}"
variable="${3:?environment variable name required}"
shift 3
[ "${1-}" = -- ] || {
    echo "expected -- before curl arguments" >&2
    exit 2
}
shift
value="${!variable-}"
[ -n "$value" ] || {
    echo "$variable is empty" >&2
    exit 2
}
if [ -n "$scheme" ]; then
    value="$scheme $value"
fi
exec curl -H @/dev/fd/3 "$@" 3<<<"$header: $value"
