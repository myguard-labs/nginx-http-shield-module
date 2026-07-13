/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * fuzz_scan.c -- libFuzzer target for the ngx_http_shield scan core.
 *
 * Fuzz surface: the exact per-input normalize + substring-scan pipeline the
 * module runs on every inspected buffer (URI, query, User-Agent, Referer,
 * Content-Type, body). For an arbitrary attacker-controlled byte string it:
 *
 *   1. builds the lowercased raw copy      (ngx_strlow)
 *   2. builds the percent-decoded copy     (ngx_unescape_uri) + '+'->' ' + lc
 *   3. runs shield_memmem over every enabled category's signatures against
 *      the raw and/or decoded buffer, per that category's match flags.
 *
 * This is byte-for-byte the logic of ngx_http_shield_scan_input() in
 * src/ngx_http_shield_module.c; the two must stay in lockstep. Keeping the
 * decoder path (ngx_unescape_uri) real -- rather than a stub -- is the whole
 * point: it is nginx's own hostile-input decoder and the buffer sizing around
 * it (dec is len bytes, decoding only ever shrinks) is what we want to prove
 * never over-reads or over-writes under ASan/UBSan.
 *
 * The signature tables are the real ones: we include the module's
 * ngx_http_shield_patterns.h unchanged, so every fuzz run scans the exact set
 * shipped in production.
 *
 * Build: see fuzz/build.sh (needs nginx source headers under .build/).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Pull in the real signature tables (types come from ngx_core.h above). */
#include "../src/ngx_http_shield_patterns.h"

/*
 * ngx_string.c is linked whole so ngx_unescape_uri()/ngx_strlow() are the real
 * decoder. That drags in three symbols from functions we never call
 * (ngx_pstrdup -> ngx_pnalloc, ngx_sort -> ngx_alloc + ngx_cycle). Satisfy the
 * linker with stubs that abort if ever reached, so a future refactor that
 * routes the scan through them is caught rather than silently mislinked.
 */
volatile ngx_cycle_t  *ngx_cycle;

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    abort();
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) size; (void) log;
    abort();
}

/* Mirror of ngx_http_shield_memmem() in the module. Kept identical: a plain
 * forward substring search that never reads past haystack+hlen. */
static u_char *
shield_memmem(u_char *haystack, size_t hlen, const char *needle, size_t nlen)
{
    u_char  *p, *last;

    if (nlen == 0 || hlen < nlen) {
        return NULL;
    }

    last = haystack + hlen - nlen;

    for (p = haystack; p <= last; p++) {
        if (*p == (u_char) needle[0] && memcmp(p, needle, nlen) == 0) {
            return p;
        }
    }

    return NULL;
}

/*
 * Faithful copy of the scan body of ngx_http_shield_scan_input(), with the
 * two scratch buffers taken from the caller (heap) instead of r->pool. The
 * skip mask is fuzzed too (first byte) so both the enabled and skipped paths
 * of the category loop are exercised.
 */
static int
shield_scan(u_char *data, size_t len, uint64_t skip)
{
    size_t                           i, j, dlen;
    u_char                          *raw_lc, *dec, *dst, *src;
    const ngx_http_shield_catdef_t  *cat;
    int                              hit = 0;

    if (len == 0) {
        return 0;
    }

    raw_lc = malloc(len);
    dec = malloc(len);
    if (raw_lc == NULL || dec == NULL) {
        free(raw_lc);
        free(dec);
        return 0;
    }

    ngx_strlow(raw_lc, data, len);

    dst = dec;
    src = data;
    ngx_unescape_uri(&dst, &src, len, 0);
    dlen = dst - dec;

    for (i = 0; i < dlen; i++) {
        if (dec[i] == '+') {
            dec[i] = ' ';
        }
    }
    ngx_strlow(dec, dec, dlen);

    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        cat = &ngx_http_shield_categories[i];

        if (skip & ((uint64_t) 1 << cat->cat)) {
            continue;
        }

        for (j = 0; j < cat->nsigs; j++) {
            const ngx_http_shield_sig_t  *sig = &cat->sigs[j];

            if ((cat->match & NGX_HTTP_SHIELD_MATCH_RAW)
                && shield_memmem(raw_lc, len, sig->s, sig->len) != NULL)
            {
                hit = 1;
                goto done;
            }

            if ((cat->match & NGX_HTTP_SHIELD_MATCH_DECODED)
                && shield_memmem(dec, dlen, sig->s, sig->len) != NULL)
            {
                hit = 1;
                goto done;
            }
        }
    }

done:
    free(raw_lc);
    free(dec);
    return hit;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t  skip = 0;
    u_char   *buf;

    /* Consume the first byte as a skip-mask selector so the fuzzer reaches
     * both the enabled and the skipped branch of the category loop. */
    if (size >= 1) {
        skip = (uint64_t) data[0] * 0x0101010101010101ULL;
        data++;
        size--;
    }

    if (size == 0) {
        return 0;
    }

    /* Copy into a fresh buffer so ngx_strlow/ngx_unescape_uri write in place
     * over a heap allocation ASan can bound-check exactly. */
    buf = malloc(size);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, data, size);

    shield_scan(buf, size, skip);

    free(buf);
    return 0;
}
