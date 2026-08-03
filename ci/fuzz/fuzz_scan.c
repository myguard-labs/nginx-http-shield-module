/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_scan.c -- libFuzzer target for the ngx_http_shield scan core.
 *
 * Fuzz surface: the exact per-input normalize + scan pipeline the module runs
 * on every inspected buffer (URI, query, User-Agent, Referer, Content-Type,
 * body). For an arbitrary attacker-controlled byte string it:
 *
 *   1. builds the lowercased raw copy      (ngx_strlow)
 *   2. builds the percent-decoded copy     (ngx_unescape_uri) + '+'->' ' + lc
 *   3. scans the raw and/or decoded buffer per each category's match flags.
 *
 * DIFFERENTIAL. The module uses an Aho-Corasick engine, which is fast but
 * non-obvious. This target runs TWO engines on every input:
 *   - the original naive per-signature memmem (shield_scan) -- simple enough to
 *     be correct by inspection, kept as the reference oracle;
 *   - the SHIPPED engine, by linking src/ngx_http_shield_scan.c and calling
 *     ngx_http_shield_scan_input() directly.
 * They must agree on hit / no-hit; a divergence aborts and libFuzzer saves the
 * input.
 *
 * The AC side used to be a hand-maintained malloc PORT of the module's engine,
 * kept in sync by comment. That made this a copy-versus-copy differential: two
 * files could agree perfectly while both diverged from what ships, and no gate
 * in the repo could see it. Since the decision seam landed
 * (src/ngx_http_shield_scan.{c,h}, which takes bytes rather than a request and
 * so links outside nginx) the port is gone and the production TU is compiled
 * in. A divergence now means the naive oracle disagrees with SHIPPED CODE,
 * which is the only version of this claim worth making.
 *
 * Input layout: 8 bytes little-endian skip mask, then 1 position-fold byte
 * (bit 0 folds ngx_http_shield_no_body_mask() -- the fold
 * ngx_http_shield_inspect_body() applies in production; bit 1 folds
 * ngx_http_shield_no_query_mask() -- the fold the URI scan applies to the
 * query-ineligible categories), then the scanned payload.
 *
 * Keeping the decoder path (ngx_unescape_uri) real -- rather than a stub -- is
 * still the point: it is nginx's own hostile-input decoder, and the buffer
 * sizing around it (dec is len bytes; decoding only ever shrinks) is what we
 * prove never over-reads or over-writes under ASan/UBSan.
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
#include <stdio.h>
#include <unistd.h>

/* Pull in the real signature tables (types come from ngx_core.h above). */
#include "../../src/ngx_http_shield_patterns.h"

/* The decision seam itself. src/ngx_http_shield_scan.c is compiled into this
 * binary by fuzz/build.sh, so the calls below reach production code. */
#include "../../src/ngx_http_shield_scan.h"

/*
 * ngx_string.c is linked whole so ngx_unescape_uri()/ngx_strlow() are the real
 * decoder, and ngx_palloc.c/ngx_alloc.c are linked for real because
 * ngx_http_shield_ac_build() builds the production automata from a real pool.
 * Between them those three define every allocator symbol the linked code
 * needs, so the only stub left is ngx_cycle -- referenced by ngx_sort(), which
 * nothing here calls.
 *
 * Formerly ngx_pnalloc() and ngx_alloc() were abort() stubs asserting the scan
 * never allocates through nginx. That assertion now lives in the seam's own
 * signature instead, and states it more strongly: ngx_http_shield_scan_input()
 * takes both scratch buffers as parameters, so the per-input path has no
 * allocator to reach for at all.
 */
volatile ngx_cycle_t  *ngx_cycle;

/*
 * Referenced by ngx_palloc.c's allocation-failure path. Output is DISCARDED:
 * the loud failure lives in shield_scan_ac_init() below, which aborts when
 * ngx_http_shield_ac_build() returns NGX_ERROR. Aborting here instead would
 * turn every nginx-internal error log into a crash, which is a wider contract
 * than this harness wants.
 */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
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
 * skip mask is fuzzed too (first eight bytes of the input, little-endian) so
 * both the enabled and skipped paths of the category loop are exercised.
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

    /* AND-rules, the same way the module evaluates them: a rule fires when
     * EVERY one of its terms is present in the SAME normalized buffer. Kept in
     * lockstep with ngx_http_shield_ac_scan() by construction -- if the module
     * grows a rule and this does not, the differential diverges and aborts,
     * which is the point.
     *
     * Note the per-buffer quantifier: all terms in the raw copy, or all terms
     * in the decoded copy. "One term raw, one term decoded" is NOT a match. */
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        const ngx_http_shield_ruledef_t  *rule = &ngx_http_shield_rules[i];
        int                               all_raw, all_dec;

        if (skip & ((uint64_t) 1 << rule->cat)) {
            continue;
        }

        all_raw = (rule->match & NGX_HTTP_SHIELD_MATCH_RAW) ? 1 : 0;
        all_dec = (rule->match & NGX_HTTP_SHIELD_MATCH_DECODED) ? 1 : 0;

        for (j = 0; j < rule->nterms; j++) {
            const ngx_http_shield_sig_t  *t = &rule->terms[j];

            if (all_raw
                && shield_memmem(raw_lc, len, t->s, t->len) == NULL)
            {
                all_raw = 0;
            }

            if (all_dec
                && shield_memmem(dec, dlen, t->s, t->len) == NULL)
            {
                all_dec = 0;
            }
        }

        if (all_raw || all_dec) {
            hit = 1;
            goto done;
        }
    }

done:
    free(raw_lc);
    free(dec);
    return hit;
}

/* ---- The SHIPPED engine ------------------------------------------------
 *
 * Not a port: src/ngx_http_shield_scan.c is compiled into this binary and
 * ngx_http_shield_scan_input() is called directly. That is the whole point of
 * the decision seam -- it takes (bytes, len, scratch, scratch) rather than an
 * ngx_http_request_t, so the production translation unit links here unchanged.
 *
 * The automata are built once from a real ngx_pool_t. ngx_create_pool() needs
 * only ngx_palloc.c/ngx_alloc.c (both linked by fuzz/build.sh) and a zeroed
 * ngx_log_t, since the stub ngx_log_error_core() below discards output.
 */

static ngx_pool_t  *shield_fuzz_pool;
static ngx_log_t    shield_fuzz_log;

static void
shield_scan_ac_init(void)
{
    ngx_memzero(&shield_fuzz_log, sizeof(shield_fuzz_log));

    /* ngx_pagesize is DEFINED by ngx_alloc.c (linked) but ASSIGNED by
     * ngx_os_init() in ngx_posix_init.c, which this binary does not link. Left
     * at 0, NGX_MAX_ALLOC_FROM_POOL is (ngx_pagesize - 1) and
     * underflows to SIZE_MAX, so ngx_create_pool() caps pool->max at the pool
     * size (16304) rather than one page. Every allocation then takes
     * ngx_palloc_small() and the large-block path is never exercised -- so the
     * harness would be fuzzing a different allocator split than production.
     * Both paths are correct, which is exactly why this is easy to miss. */
    ngx_pagesize = (ngx_uint_t) getpagesize();

    shield_fuzz_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE,
                                       &shield_fuzz_log);
    if (shield_fuzz_pool == NULL) {
        fprintf(stderr, "SHIELD FUZZ: ngx_create_pool failed\n");
        abort();
    }

    /* A failed build would leave an empty automaton that matches nothing --
     * silently turning the differential into "naive says hit, AC says no" on
     * every input. Abort loudly instead. */
    if (ngx_http_shield_ac_build(shield_fuzz_pool, &shield_fuzz_log,
                                 &ngx_http_shield_ac_decoded,
                                 NGX_HTTP_SHIELD_MATCH_DECODED)
        != NGX_OK)
    {
        fprintf(stderr, "SHIELD FUZZ: ac_build(decoded) failed\n");
        abort();
    }

    if (ngx_http_shield_ac_build(shield_fuzz_pool, &shield_fuzz_log,
                                 &ngx_http_shield_ac_raw,
                                 NGX_HTTP_SHIELD_MATCH_RAW)
        != NGX_OK)
    {
        fprintf(stderr, "SHIELD FUZZ: ac_build(raw) failed\n");
        abort();
    }
}

/*
 * Run the production scanner and reduce its verdict to hit / no-hit.
 *
 * The scratch buffers are malloc'd per call, exactly len bytes each and freed
 * immediately, so ASan bounds-checks the module's writes into them precisely.
 * A pool allocation would round up and hide a one-byte overrun.
 *
 * "body" is passed as the source string only because the seam requires one;
 * the position folds that actually vary the scan are applied to the skip mask
 * by the caller, as they are in production.
 */
static int
shield_scan_ac(u_char *data, size_t len, uint64_t skip)
{
    int                     hit;
    u_char                 *raw_lc, *dec;
    ngx_http_shield_hit_t   h;

    raw_lc = malloc(len);
    dec = malloc(len);
    if (raw_lc == NULL || dec == NULL) {
        free(raw_lc);
        free(dec);
        return 0;
    }

    ngx_memzero(&h, sizeof(h));

    hit = (ngx_http_shield_scan_input(data, len, raw_lc, dec, "body", skip, &h)
           == NGX_OK);

    free(raw_lc);
    free(dec);
    return hit;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t   skip = 0;
    u_char    *buf;
    static int built;

    if (!built) {
        shield_scan_ac_init();
        built = 1;
    }

    /* Consume the first eight bytes (explicit little-endian decode) as the
     * FULL skip mask. Expanding a single byte across the mask tied together
     * every pair of categories whose enum positions agree modulo 8, so the
     * oracle could never skip one while leaving the other enabled -- the
     * exact cross-category masking class this harness exists to find. */
    if (size >= 8) {
        size_t  i;

        for (i = 0; i < 8; i++) {
            skip |= (uint64_t) data[i] << (i * 8);
        }
        data += 8;
        size -= 8;
    }

    if (size == 0) {
        return 0;
    }

    /* One more byte selects the position-fold mode. The module folds a
     * position mask into the skip mask at specific scan sites only:
     *   bit 0 -> ngx_http_shield_no_body_mask(), on the body scan;
     *   bit 1 -> ngx_http_shield_no_query_mask(), on the whole-target scan of
     *            the URI (the query-ineligible categories).
     * Fuzzing these dimensions independently -- rather than only ever scanning
     * as if this were an unmasked path/header -- exercises the folds themselves:
     * a category wrongly left out of (or wrongly added to) either mask would
     * otherwise never surface as a differential, since both engines below would
     * just agree on the wrong answer. */
    if (data[0] & 1) {
        skip |= ngx_http_shield_no_body_mask();
    }
    if (data[0] & 2) {
        skip |= ngx_http_shield_no_query_mask();
    }
    data += 1;
    size -= 1;

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

    /* Differential: the naive engine (obvious-by-inspection reference) and the
     * shipped Aho-Corasick engine must agree that this input is a hit or not.
     * Both read the same signature table; a divergence is a real bug in the
     * rewrite and aborts so libFuzzer records the input. */
    {
        int naive = shield_scan(buf, size, skip);
        int ac = shield_scan_ac(buf, size, skip);
        if (naive != ac) {
            fprintf(stderr,
                    "SHIELD DIFFERENTIAL: naive=%d ac=%d len=%zu skip=%#llx\n",
                    naive, ac, size, (unsigned long long) skip);
            abort();
        }
    }

    free(buf);
    return 0;
}
