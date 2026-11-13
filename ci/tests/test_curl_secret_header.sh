#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/curl" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$ARGV_OUT"
cat <&3 >"$HEADER_OUT"
SCRIPT
chmod +x "$tmp/curl"
export PATH="$tmp:$PATH" ARGV_OUT="$tmp/argv" HEADER_OUT="$tmp/header"
export CANARY_TOKEN='canary-token-with spaces and "quotes"'
"$root/.github/scripts/curl-secret-header.sh" \
    Authorization Bearer CANARY_TOKEN -- -fsS https://example.invalid/
grep -qxF 'Authorization: Bearer canary-token-with spaces and "quotes"' "$HEADER_OUT"
if grep -qF "$CANARY_TOKEN" "$ARGV_OUT"; then
    echo "secret leaked into curl argv" >&2
    exit 1
fi
grep -qxF 'https://example.invalid/' "$ARGV_OUT"
printf 'ok   secret header reaches curl fd without entering argv\n'
