#!/usr/bin/env bash
# sync-sha: 8bf3b9f698a52cd34b908097b11d1bc1aa77fed7536250252de4a26bc286d6ff
# Pass a secret-backed HTTP header to curl without exposing its value in argv.
set -euo pipefail

header="${1:?header name required}"
scheme="${2-}"
variable="${3:?environment variable name required}"
shift 3
[ "${1-}" = -- ] || { echo "expected -- before curl arguments" >&2; exit 2; }
shift
value="${!variable-}"
[ -n "$value" ] || { echo "$variable is empty" >&2; exit 2; }
if [ -n "$scheme" ]; then
    value="$scheme $value"
fi
exec curl -H @/dev/fd/3 "$@" 3<<<"$header: $value"
