/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_xff.c -- libFuzzer target for the X-Forwarded-For token parse.
 *
 * Fuzz surface: ngx_http_shield_xff_last_token(), the only part of ban keying
 * that consumes attacker-supplied bytes. When `shield_ban key=forwarded` is
 * configured and the peer is a trusted proxy, this parse decides which address
 * the ban is keyed on -- so a defect here does not corrupt memory quietly, it
 * picks the wrong victim. Getting it wrong in the other direction is worse:
 * a token the attacker can vary per request means the ban threshold is never
 * reached and the real client is never banned.
 *
 * The input is the raw header value, used whole. No length prefix and no mode
 * byte: the function takes bytes and a length, and every byte string is a
 * legal header value as far as it is concerned. nginx has already rejected
 * NUL and control bytes in a header value by the time this runs in production,
 * but the function does not rely on that and neither does this target.
 *
 * DIFFERENTIAL. xff_naive() below re-derives the same answer by a deliberately
 * different route: it copies the value, splits on commas by walking FORWARD
 * and remembering the last segment, then trims. The shipped implementation
 * scans BACKWARD from the end for the first comma and trims in place. Two
 * directions over the same grammar should agree on every input; where they do
 * not, one of them mishandles an edge (a trailing comma, an all-whitespace
 * element, an empty value) and libFuzzer records it.
 *
 * A pure ASan target here would be weak: the function does no allocation and
 * writes nothing, so its realistic failure mode is a WRONG ANSWER within
 * bounds -- an off-by-one that includes the comma, a trim that eats a byte of
 * the address, a backward scan that walks before `value` on an empty string.
 * ASan sees none of those. The oracle does.
 *
 * The shipped code is linked, not copied: src/ngx_http_shield_ban.c depends
 * only on <ngx_core.h>, which is what makes this possible at all. Keeping the
 * naive side in this file rather than in the module is deliberate -- if it
 * lived next to the real one, a single wrong idea would be edited into both.
 *
 * Build: see ci/fuzz/build.sh.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../../src/ngx_http_shield_ban.h"

/*
 * Referenced by ngx_palloc.c's allocation-failure path, which is linked for
 * the allocator symbols even though this target never allocates through a
 * pool. Output is discarded; nothing here logs.
 */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}


volatile ngx_cycle_t  *ngx_cycle;


/*
 * ngx_http_shield_ban.c is linked whole for one function, so the ban state
 * engine's slab calls have to resolve even though nothing here reaches them.
 * Backed by malloc, the same way ci/t/ban_unit.c does it -- see that file for
 * why a fake is correct rather than lazy: the slab is shared-memory
 * infrastructure, and the code under test never inspects the pool it is given.
 *
 * If a future change makes this target actually exercise the ban tree, these
 * must be revisited; today an unreachable stub is honest about what is fuzzed.
 * ngx_rbtree.c is linked for real because the tree code is small, has no
 * external dependencies, and faking it would prove less than linking it.
 */
void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}


void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    (void) pool;
    free(p);
}


/*
 * The reference oracle: same grammar, opposite traversal.
 *
 * Walks forward over the value, treating every comma as a separator and
 * keeping the most recent segment, then trims spaces and tabs off both ends.
 * Writes the result as offsets into the ORIGINAL buffer so the comparison
 * below can check the pointer as well as the length -- a token of the right
 * length taken from the wrong place is exactly the kind of bug worth catching.
 */
static void
xff_naive(u_char *value, size_t len, size_t *out_off, size_t *out_len)
{
    size_t  i, seg_start, seg_end;

    seg_start = 0;
    seg_end = len;

    for (i = 0; i < len; i++) {
        if (value[i] == ',') {
            seg_start = i + 1;
        }
    }

    while (seg_start < seg_end
           && (value[seg_start] == ' ' || value[seg_start] == '\t'))
    {
        seg_start++;
    }

    while (seg_end > seg_start
           && (value[seg_end - 1] == ' ' || value[seg_end - 1] == '\t'))
    {
        seg_end--;
    }

    *out_off = seg_start;
    *out_len = seg_end - seg_start;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char     *buf;
    ngx_str_t   got;
    size_t      want_off, want_len;

    /* A fresh exact-sized heap buffer, so ASan brackets both ends: the
     * backward comma scan and the two trim loops all compute pointers from
     * `value` and `value + len`, and an off-by-one in any of them steps
     * directly into a redzone. A stack array or an over-allocated buffer would
     * absorb the same mistake silently. */
    buf = malloc(size ? size : 1);
    if (buf == NULL) {
        return 0;
    }
    if (size) {
        memcpy(buf, data, size);
    }

    ngx_memzero(&got, sizeof(got));
    ngx_http_shield_xff_last_token(buf, size, &got);

    xff_naive(buf, size, &want_off, &want_len);

    /* The result must point INTO the input, never past either end. Checked
     * explicitly because the caller turns this into (data, len) for
     * ngx_parse_addr_port(), which will happily read whatever it is handed. */
    if (got.data < buf || got.data + got.len > buf + size) {
        fprintf(stderr,
                "SHIELD XFF: token escapes the buffer: "
                "off=%td len=%zu size=%zu\n",
                (ptrdiff_t) (got.data - buf), got.len, size);
        abort();
    }

    if ((size_t) (got.data - buf) != want_off || got.len != want_len) {
        fprintf(stderr,
                "SHIELD XFF DIFFERENTIAL: shipped=(off=%td len=%zu) "
                "naive=(off=%zu len=%zu) size=%zu\n",
                (ptrdiff_t) (got.data - buf), got.len,
                want_off, want_len, size);
        abort();
    }

    free(buf);
    return 0;
}
