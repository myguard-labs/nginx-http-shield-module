#!/usr/bin/env bash
# ci/linter/lint-nginx.sh -- nginx-specific source conventions for src/*.[ch].
#
# What no generic C linter knows: an nginx module must use the nginx allocator,
# the nginx string/number helpers and the nginx source style, because it is
# compiled into a worker with a pool-based lifetime and a shared coding
# standard. flawfinder/cppcheck/semgrep all pass code that leaks a malloc()
# into a request pool or calls atoi() on attacker input.
#
# Checks (each one line per finding, "file:line: rule: text"):
#   libc-alloc   malloc/calloc/realloc/free      -> ngx_palloc/ngx_pcalloc/ngx_pfree
#   libc-str     strcpy/strcat/sprintf/strncpy   -> ngx_cpymem/ngx_snprintf
#   libc-num     atoi/atol/strtol on request data -> ngx_atoi/ngx_atoof
#   libc-io      bare printf/fprintf(stderr)     -> ngx_log_error
#   tabs         hard tab in source              -> nginx style is 4 spaces
#   width        line >80 columns                -> nginx style limit (OPT-IN, see below)
#   trailing     trailing whitespace
#   include      .c must include ngx_config.h before ngx_core.h
#
# Suppress a single justified line with a trailing  /* NOLINT-nginx */ .
# Suppressing a whole rule is not supported on purpose: the exception belongs
# next to the code that needs it, where review can see the reason.
#
# LINT_NGINX_WIDTH=1 -- the 80-column rule is OFF by default, unlike every
# other rule here. This repo's src/*.[ch] predates this checker and carries
# long single-line rationale/CVE-context comments and one wide signature/URL
# table (ngx_http_shield_patterns.h) that were never written to an 80-column
# limit: 127 pre-existing hits across all 8 files as of the checker's
# introduction (cp7b-1). Reflowing that prose risks silently changing meaning
# in security-sensitive comments and is tracked as its own backlog item
# (memory/labs/nginx-http-shield-module/TODO.md) rather than bundled into a
# linter-porting change. Every OTHER rule in this file is clean today and
# gates unconditionally -- this is a scoped, documented exception on ONE rule,
# not a disabled checker: set LINT_NGINX_WIDTH=1 to include it.
#
# Usage: ci/linter/lint-nginx.sh [files...]   Env: LINT_MODE=staged|all
#                                              LINT_NGINX_WIDTH=1 (see above)
# Extend: add a rule as one more `rule <name> <regex> <message>` call.

# shellcheck source=ci/linter/lib.sh disable=SC1091
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '^src/.*\.[ch]$' "$@")
[ "${#FILES[@]}" -gt 0 ] || {
    echo "lint-nginx: no C files to check"
    exit 0
}

echo "lint-nginx: ${#FILES[@]} file(s)"
rc=0

# rule <name> <ere> <message> -- report every matching line not marked NOLINT.
rule() {
    local name="$1" re="$2" msg="$3" hits
    hits=$(grep -nE "$re" "${FILES[@]}" 2>/dev/null | grep -v 'NOLINT-nginx' || true)
    [ -n "$hits" ] || return 0
    # printf, not sed -- every replacement message here (this repo's
    # libc-alloc/libc-str messages say "ngx_palloc/ngx_pcalloc/ngx_pfree")
    # contains a literal '/', and interpolating it into a sed s/// program
    # whose delimiter IS '/' breaks with "unknown option to `s'" instead of
    # reporting the finding -- a lint bug that reads as a clean run.
    while IFS= read -r line; do
        printf '  %s    [%s: %s]\n' "$line" "$name" "$msg"
    done <<<"$hits"
    rc=1
}

# No [[:space:]]* before the '(' on any of these four: a real C call in this
# tree's style is always `name(`, never `name (`. The looser form used to
# match prose too -- "...did NOT free (it advances to..." in a block comment
# read as a call to free() -- one false positive found when the sed-delimiter
# bug above was fixed and this rule finally got to report anything. Tightened
# instead of NOLINT-ing the comment: `/* NOLINT-nginx */` cannot be inserted
# mid-block-comment without prematurely closing it (nested /* */ is not legal
# C), so the false positive had no safe inline suppression -- the regex was
# the actual bug.
rule libc-alloc '(^|[^_[:alnum:]])(malloc|calloc|realloc|free)\(' \
    'use ngx_palloc/ngx_pcalloc/ngx_pfree'
rule libc-str '(^|[^_[:alnum:]])(strcpy|strcat|sprintf|strncpy|strncat)\(' \
    'use ngx_cpymem/ngx_snprintf'
rule libc-num '(^|[^_[:alnum:]])(atoi|atol|strtol|strtoul)\(' \
    'use ngx_atoi/ngx_atoof'
rule libc-io '(^|[^_[:alnum:]])(printf|fprintf|perror)\(' \
    'use ngx_log_error/ngx_conf_log_error'
rule tabs $'\t' 'nginx style is 4 spaces, no hard tabs'
rule trailing '[[:space:]]+$' 'trailing whitespace'
if [ -n "${LINT_NGINX_WIDTH:-}" ]; then
    rule width '^.{81,}$' 'nginx style limit is 80 columns'
else
    say "width rule SKIPPED (LINT_NGINX_WIDTH unset) -- see header, tracked in TODO.md"
fi

for f in "${FILES[@]}"; do
    case "$f" in
        *.c)
            # ngx_config.h defines the feature macros every later nginx header
            # reads; including ngx_core.h first silently changes the build. Look at
            # the FIRST ngx_ include, not a fixed head -N window: these files open
            # with a long licence/design comment that would push the includes out
            # of any window and make the check vacuous.
            # Angle brackets only: a local "ngx_http_<mod>_*.h" is this module's
            # own header and carries its own ngx_config.h include -- matching it
            # here reported every well-formed file.
            first_ngx=$(grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<ngx_' "$f" | head -1 || true)
            if [ -n "$first_ngx" ] && ! printf '%s' "$first_ngx" | grep -q 'ngx_config\.h'; then
                printf '  %s:    [include: ngx_config.h must be the first ngx_ include]\n' \
                    "$f:${first_ngx%%:*}"
                rc=1
            fi
            ;;
    esac
done

if [ "$rc" -eq 0 ]; then say "clean"; fi
exit "$rc"
