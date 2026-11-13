#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
    local fixture="$1" file
    mkdir -p "$fixture/bin"
    for file in \
        ci/tools/bump-tools.sh \
        .github/workflows/security-scanners.yml \
        .github/workflows/ci-deep.yml \
        .github/workflows/build-test.yml \
        ci/linter/install-linters.sh \
        ci/linter/lint-c.sh \
        ci/dependency-inventory.json \
        ci/tests/test_bump_tools_semgrep.sh; do
        mkdir -p "$fixture/$(dirname "$file")"
        cp "$root/$file" "$fixture/$file"
    done
    cat >"$fixture/bin/curl" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' '{"info":{"version":"9.9.9"}}'
SCRIPT
    chmod +x "$fixture/bin/curl"
}

good="$tmp/good"
make_fixture "$good"
PATH="$good/bin:$PATH" "$good/ci/tools/bump-tools.sh" >"$good/out"
grep -q 'TOOLS_CHANGED=1' "$good/out"
for file in \
    .github/workflows/security-scanners.yml \
    .github/workflows/ci-deep.yml \
    ci/linter/install-linters.sh \
    ci/linter/lint-c.sh; do
    grep -q '9\.9\.9' "$good/$file"
    if grep -q '1\.184\.0' "$good/$file"; then
        echo "stale Semgrep pin remained in $file" >&2
        exit 1
    fi
done
jq -e '.dependencies[] | select(.id == "semgrep") | .version == "9.9.9"' \
    "$good/ci/dependency-inventory.json" >/dev/null
for file in \
    .github/workflows/build-test.yml \
    .github/workflows/security-scanners.yml \
    .github/workflows/ci-deep.yml \
    ci/linter/install-linters.sh; do
    old_zizmor=1.31.1
    new_zizmor=9.9.9
    grep -q "zizmor==${new_zizmor}\\|ZIZMOR_VERSION: \"${new_zizmor}\"" "$good/$file"
    if grep -q "zizmor==${old_zizmor}\\|ZIZMOR_VERSION: \"${old_zizmor}\"" "$good/$file"; then
        echo "stale zizmor pin remained in $file" >&2
        exit 1
    fi
done
jq -e '.dependencies[] | select(.id == "zizmor") | .version == "9.9.9"' \
    "$good/ci/dependency-inventory.json" >/dev/null
old_ruff=0.16.1
new_ruff=9.9.9
grep -q "ruff==${new_ruff}" "$good/ci/linter/install-linters.sh"
if grep -q "ruff==${old_ruff}" "$good/ci/linter/install-linters.sh"; then
    echo "stale Ruff pin remained in ci/linter/install-linters.sh" >&2
    exit 1
fi
jq -e '.dependencies[] | select(.id == "ruff") | .version == "9.9.9"' \
    "$good/ci/dependency-inventory.json" >/dev/null
jq -e '.pin_checks[] | select(.pattern | contains("ruff")) | .expected == "9.9.9"' \
    "$good/ci/dependency-inventory.json" >/dev/null

missing="$tmp/missing"
make_fixture "$missing"
sed -E -i 's/semgrep==[0-9]+(\.[0-9]+)*/semgrep/' "$missing/ci/linter/lint-c.sh"
if PATH="$missing/bin:$PATH" "$missing/ci/tools/bump-tools.sh" >"$missing/out" 2>&1; then
    echo "missing listed Semgrep pin unexpectedly passed" >&2
    exit 1
fi
grep -q "no pin found in listed file 'ci/linter/lint-c.sh'" "$missing/out"

stray="$tmp/stray"
make_fixture "$stray"
PATH="$stray/bin:$PATH" "$stray/ci/tools/bump-tools.sh" >/dev/null
printf '%s%s\n' '# semgrep==' '1.184.0' >"$stray/ci/stale.sh"
if PATH="$stray/bin:$PATH" "$stray/ci/tools/bump-tools.sh" >"$stray/out" 2>&1; then
    echo "unlisted stale Semgrep pin unexpectedly passed" >&2
    exit 1
fi
grep -q 'pins disagree after bump' "$stray/out"

printf 'ok   tool bumps update Semgrep/zizmor/Ruff pins and reject missing or stray copies\n'
