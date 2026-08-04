#!/usr/bin/env bash
#
# Build nginx (or angie) with the shield module for local testing and CI.
#
#   ci/tools/ci-build.sh [flavor] [version] [mode]
#     flavor : nginx (default) | angie
#     version: source version, e.g. 1.31.3 (default: the pin in
#              .github/versions.env for the chosen flavor)
#     mode   : debug (default, dynamic .so) | asan (static, sanitizers)
#              | module (dynamic .so only, nginx core NOT compiled)
#              | coverage (static, gcov-instrumented module TU)
#
# Every version this script is asked to build must have a matching sha256 in
# .github/versions.env -- see the integrity block below.
#
# The built tree lives under ./.build, one tree PER MODE so a mode switch
# never reuses another mode's object files: .build/<flavor>-<version>-<mode>.
# On success the paths of interest are:
#   .build/<dir>/objs/nginx                         (server binary)
#   .build/<dir>/objs/ngx_http_shield_module.so     (debug/module mode)
#
# "module" mode exists for CodeQL. For compiled languages CodeQL builds its
# database from whatever the traced build actually compiles -- the workflow's
# paths/paths-ignore filters do NOT apply to C/C++. Building the nginx core
# therefore pulled all of nginx into the database and raised alerts against
# upstream code we neither own nor patch. Compiling only the module keeps the
# database limited to our translation unit.

set -euo pipefail

FLAVOR="${1:-nginx}"

# Version pins (and their sha256s) all come from .github/versions.env -- see
# the integrity block below. Sourced this early so the default version tracks
# the pinned one instead of being a literal that silently rots.
MODULE_DIR="$PWD"
VERSIONS_FILE="${VERSIONS_FILE:-$MODULE_DIR/.github/versions.env}"
if [ ! -f "$VERSIONS_FILE" ]; then
    echo "FATAL: $VERSIONS_FILE not found (run from the module root)" >&2
    exit 1
fi
# Validate before sourcing: a line in this file that is not a pin would be
# executed as shell. Shared with every other consumer -- see
# ci/tools/versions-env.sh.
# shellcheck source=ci/tools/versions-env.sh disable=SC1091
. "$MODULE_DIR/ci/tools/versions-env.sh"
load_versions_env "$VERSIONS_FILE" || exit 1

case "$FLAVOR" in
    nginx) DEFAULT_VERSION="${NGINX_VERSION:-}" ;;
    angie) DEFAULT_VERSION="${ANGIE_VERSION:-}" ;;
    *) DEFAULT_VERSION="" ;;
esac
VERSION="${2:-$DEFAULT_VERSION}"
MODE="${3:-debug}"

case "$MODE" in
    debug | asan | module | coverage) ;;
    *)
        echo "unsupported mode: $MODE (want: debug|asan|module|coverage)" >&2
        exit 2
        ;;
esac
ROOT="${BUILD_ROOT:-$PWD/.build}"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        TARBALL_STEM="nginx-${VERSION}"
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        TARBALL_STEM="angie-${VERSION}"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac
# The downloaded tarball is shared/cached across modes (identical bytes for a
# given flavor+version), but the UNPACKED build tree is mode-specific: a
# shared tree would let a mode switch reuse another mode's stale object
# files (e.g. a coverage-instrumented .o silently linked into an asan build).
DIR="${TARBALL_STEM}-${MODE}"

# --- integrity: sha256 pins come from .github/versions.env -----------------
# nginx.org serves plain HTTP-adjacent PGP signatures, not a sha256sum file, so
# "verify against the vendor" means pinning a known-good digest for each source
# tarball we build. Version (workflow env / this script's default) and digest
# now live on adjacent lines in .github/versions.env, written by one tool
# (.github/scripts/compute-versions.sh), so a bumped version with a stale
# digest can no longer happen.
#
# Verification is MANDATORY: a version with no digest here is a hard failure,
# not a warning. (versions.env was already sourced above, to default $VERSION.)
if [ -z "$VERSION" ]; then
    # Guard before the case below: an empty $VERSION would match an empty
    # "${NGINX_STABLE:-}" pattern and silently adopt the wrong digest.
    echo "FATAL: no version given and no default pin for flavor '$FLAVOR'" >&2
    exit 1
fi
EXPECTED=""
case "$FLAVOR" in
    nginx)
        case "$VERSION" in
            "${NGINX_VERSION:-}") EXPECTED="${NGINX_VERSION_SHA256:-}" ;;
            "${NGINX_STABLE:-}") EXPECTED="${NGINX_STABLE_SHA256:-}" ;;
        esac
        ;;
    angie)
        case "$VERSION" in
            "${ANGIE_VERSION:-}") EXPECTED="${ANGIE_VERSION_SHA256:-}" ;;
        esac
        ;;
esac

if [ -z "$EXPECTED" ]; then
    echo "FATAL: no pinned sha256 for $FLAVOR $VERSION" >&2
    echo "  $VERSIONS_FILE pins:" >&2
    echo "    nginx  ${NGINX_VERSION:-?} (stable ${NGINX_STABLE:-?})" >&2
    echo "    angie  ${ANGIE_VERSION:-?}" >&2
    echo "  Regenerate it with .github/scripts/compute-versions.sh, or add the" >&2
    echo "  version + its sha256 there -- never build an unverified tarball." >&2
    exit 1
fi

mkdir -p "$ROOT"
# fetch-verify.sh downloads (with retries/timeouts) and checks the digest. It
# re-checks a tarball already present in .build/ rather than trusting it, so a
# poisoned build cache is caught too -- a poisoned Actions cache is exactly as
# dangerous as a poisoned mirror, and HTTPS stops neither.
# The tarball itself is cached under its flavor+version stem, shared across
# modes (identical bytes regardless of mode) -- only the unpacked tree below
# is mode-specific.
if ! bash "$MODULE_DIR/.github/scripts/fetch-verify.sh" \
    "$URL" "$EXPECTED" "$ROOT/${TARBALL_STEM}.tar.gz"; then
    # A tarball that fails verification must not survive to be picked up as a
    # "cache hit" by the next run.
    rm -f "$ROOT/${TARBALL_STEM}.tar.gz"
    exit 1
fi

# Unpack into a mode-specific tree: the tarball's own top-level dir is
# $TARBALL_STEM (no mode suffix), so extract into a scratch dir and move it
# into place under $DIR. This is what actually gives each mode its own object
# files -- extracting straight to $ROOT would collide across modes.
if [ ! -d "$ROOT/$DIR" ]; then
    scratch="$(mktemp -d "$ROOT/.unpack-XXXXXX")"
    tar -xzf "$ROOT/${TARBALL_STEM}.tar.gz" -C "$scratch"
    mv "$scratch/$TARBALL_STEM" "$ROOT/$DIR"
    rmdir "$scratch"
fi

# --with-cc-opt applies to UPSTREAM CORE as well as to our module, so it must
# carry only flags that upstream compiles cleanly under. -Wshadow does not
# qualify: angie 1.12.0's own ngx_http_client_module.c shadows a parameter, and
# angie's configure adds -Werror, so a -Wshadow here fails the core build before
# our code is ever reached. (nginx core happens to be -Wshadow-clean; that is
# luck, not a contract.)
#
# The module is hostile-input parser code and still gets the strict treatment --
# but scoped to its own translation unit by the "Strict module compile" step in
# build-test.yml, which recompiles src/ with -Wshadow -Werror and friends. That
# is the right boundary: our warnings are our problem, upstream's are not.
CC_OPT="-g -Wall"
LD_OPT=""
ADD_MODULE="--add-dynamic-module=$MODULE_DIR"

if [ "$MODE" = "asan" ]; then
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
    SAN="$SAN -fno-omit-frame-pointer -g -O1"
    if "${CC:-cc}" --version 2>/dev/null | grep -qi clang; then
        # nginx core trips a few benign UBSan sub-checks; silence only those.
        SAN="$SAN -fno-sanitize=function,nonnull-attribute,pointer-overflow"
    fi
    CC_OPT="$SAN -Wall"
    LD_OPT="$SAN"
    # Static build so the sanitizer runtime is linked into the server binary.
    ADD_MODULE="--add-module=$MODULE_DIR"
fi

if [ "$MODE" = "coverage" ]; then
    # gcov instrumentation. --coverage == -fprofile-arcs -ftest-coverage; it is
    # applied core-wide (configure has no per-module cc-opt hook), but the CI job
    # harvests gcov only for our translation unit, so upstream .gcda is ignored.
    # Static link (--add-module) so the instrumented module runs inside the very
    # server binary the tests drive, and .gcda lands next to objs/.
    CC_OPT="-g -O0 --coverage -Wall"
    LD_OPT="--coverage"
    ADD_MODULE="--add-module=$MODULE_DIR"
fi

# TEST_HARNESS=1 compiles the CI-only shield_probe introspection endpoint into
# the module (ci/t/harness/src/ngx_test_probe.c plus the shield-specific hooks in
# src/ngx_shield_probe_hooks.c). Off by default and never set by the
# .deb build, so the endpoint cannot reach a shipped package. The define goes
# through --with-cc-opt, so it is visible core-wide -- harmless, since only our
# TUs test for it.
if [ "${TEST_HARNESS:-0}" = "1" ]; then
    CC_OPT="$CC_OPT -DNGX_TEST_HARNESS"
fi

# angie names its server binary objs/angie, nginx names it objs/nginx. Report
# the path that actually exists -- the old hardcoded objs/nginx was a lie on the
# angie leg, and any caller that trusted it got "No such file or directory".
BIN="nginx"
if [ "$FLAVOR" = "angie" ]; then
    BIN="angie"
fi

cd "$ROOT/$DIR"

./configure \
    --with-compat \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

case "$MODE" in
    asan | coverage)
        make -j"$(nproc)"
        echo "built: $ROOT/$DIR/objs/$BIN"
        ;;
    module)
        # Only the module .so -- deliberately no full `make`, so the nginx core
        # is never compiled and never enters a traced CodeQL database.
        make -j"$(nproc)" modules
        echo "built: $ROOT/$DIR/objs/ngx_http_shield_module.so"
        ;;
    *)
        make -j"$(nproc)" modules
        make -j"$(nproc)"
        echo "built: $ROOT/$DIR/objs/$BIN"
        ;;
esac
