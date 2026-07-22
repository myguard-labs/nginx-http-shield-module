#!/usr/bin/env bash
#
# Run the shield prober rules against a probe-enabled build.
#
#   t/prober/run.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what tools/ci-build.sh fetched
#
# The engine lives in t/harness (nginx-test-harness) and knows nothing about
# shield: this only supplies the four things that are shield's -- which .so to
# look in, which directive proves the harness build, and where the conf and
# rules are. Everything else (boot, teardown, TAP, the delta engine, the pid
# oracle, the error-log scrape) is the harness's.
#
# The build must have been made with TEST_HARNESS=1, otherwise shield_probe
# does not exist and the config fails to load; the harness checks for that up
# front by inspecting the binary rather than letting it surface as a confusing
# connect error.
set -euo pipefail

cd "$(dirname "$0")"

HERE="$PWD"

if [ ! -x ../harness/prober/run.sh ]; then
    echo "Bail out! t/harness is empty -- run: git submodule update --init"
    exit 1
fi

# The harness resolves conf/rules relative to its own directory, so both are
# passed as absolute paths out of this one.
export PROBER_MODULE="ngx_http_shield_module.so"
export PROBER_DIRECTIVE="shield_probe"
export PROBER_CONF="$HERE/conf/prober.conf"
export PROBER_RULES="$HERE/rules/*.rule"
# SC2155: split declare from assign so a failed cd/pwd surfaces its exit status
# instead of being masked by export's own success.
PROBER_ROOT="$(cd ../.. && pwd)"
export PROBER_ROOT

# NOT setting PROBER_ALLOW_LOG on purpose. 04-fault.rule drives the slab
# allocator to failure, which is the kind of thing that usually has to be
# exempted from the harness's [alert]/[crit]/[emerg] gate -- but shield logs
# its zone-full path at [warn] (ngx_http_shield_ban_record_locked) and nginx
# core logs nothing at all when a module's own slab_alloc returns NULL, so
# there is nothing to exempt. Verified by scraping the log across a full fault
# run, 2026-07-18. An allowlist here would be a blanket exemption for a
# condition that does not occur, and would silently cover a real [crit] the
# day one appears.

exec ../harness/prober/run.sh "$@"
